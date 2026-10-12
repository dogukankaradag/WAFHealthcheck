"""WAF Healthcheck — web arayüzü + REST API (FastAPI).

fwcheck (FirewallAudit) ile aynı yapı:
  Kimlik      POST /api/auth/login · GET /api/auth/me · /api/auth/users (admin)
  Tarama      GET /api/connectors · POST /api/scan (admin, manuel) · GET /api/scan/status · GET /api/scan/history
  Görünüm     GET /api/summary · /api/devices · /api/partitions · /api/findings · /api/findings/check-names
  İş akışı    PATCH /api/findings/{fingerprint}/status (admin)
  Rapor       GET /api/report/{html|xlsx|csv|json}?token=...&session_id=...
  Arayüz      GET /

Otomatik/zamanlanmış tarama yoktur; taramalar yalnızca arayüzden (veya CLI'dan) manuel başlatılır.
Kimlik: 'Authorization: Bearer <token>', rapor indirmede '?token=', otomasyon için 'X-API-Key' (admin sayılır).
"""
from __future__ import annotations

import logging
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from .auth import (ROLES, LoginThrottle, TokenSigner, ensure_default_admin, hash_password,
                   password_problem, verify_password)
from .checks import catalog
from .models import SEVERITIES, SEVERITY_WEIGHT, Config
from .reporters import write_all
from .scanner import Scanner
from .state import WORKFLOW_STATUSES, StateStore

log = logging.getLogger("f5waf.api")

CFG = Config.load(os.environ.get("F5WAF_CONFIG", "config.yaml"))
STORE = StateStore(CFG.state_db)
SIGNER = TokenSigner(STORE)
THROTTLE = LoginThrottle()
WEB_DIR = Path(__file__).parent / "web"

_scan_lock = threading.Lock()
PROGRESS: dict[str, dict] = {}       # scan_id -> {"devices": {ad: {...}}}
_FINDINGS_CACHE: dict[str, list] = {}  # tamamlanmış taramalar değişmez


@asynccontextmanager
async def lifespan(app: FastAPI):
    n = STORE.mark_interrupted()
    if n:
        log.warning("%d yarım kalmış tarama 'failed' olarak işaretlendi", n)
    ensure_default_admin(STORE, log)
    yield


app = FastAPI(title="WAF Healthcheck API", version="2.0.0", docs_url="/api/docs",
              redoc_url=None, lifespan=lifespan)


# =================================================================== kimlik
def current_user(request: Request, authorization: Optional[str] = Header(default=None),
                 x_api_key: Optional[str] = Header(default=None),
                 token_q: Optional[str] = Query(default=None, alias="token")) -> dict:
    if x_api_key and CFG.api_keys and x_api_key in CFG.api_keys:
        return {"id": 0, "username": "api-key", "full_name": "API anahtarı", "role": "admin"}
    raw = token_q
    if authorization and authorization.lower().startswith("bearer "):
        raw = authorization[7:]
    data = SIGNER.verify(raw) if raw else None
    user = STORE.get_user(data["sub"]) if data else None
    if not user or not user["is_active"]:
        raise HTTPException(401, "Geçersiz veya süresi dolmuş oturum. Lütfen tekrar giriş yapın.")
    return {k: user[k] for k in ("id", "username", "full_name", "role")}


def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "Bu işlem için admin yetkisi gereklidir.")
    return user


@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    uname = form.username.strip()
    wait = THROTTLE.blocked(uname)
    if wait:
        raise HTTPException(429, f"Çok fazla hatalı deneme. {wait} sn sonra tekrar deneyin.")
    user = STORE.get_user(uname)
    if not user or not user["is_active"] or not verify_password(form.password, user["password_hash"]):
        THROTTLE.fail(uname)
        raise HTTPException(401, "Kullanıcı adı veya parola hatalı.")
    THROTTLE.reset(uname)
    return {"access_token": SIGNER.issue(user["username"], user["role"]), "token_type": "bearer",
            "username": user["username"], "full_name": user["full_name"], "role": user["role"]}


@app.get("/api/auth/me")
def me(user: dict = Depends(current_user)):
    return user


class UserCreate(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = ""
    role: str = "readonly"


class UserEdit(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None


def _active_admins() -> list[dict]:
    return [u for u in STORE.list_users() if u["role"] == "admin" and u["is_active"]]


@app.get("/api/auth/users")
def list_users(_: dict = Depends(require_admin)):
    return STORE.list_users()


@app.post("/api/auth/users", status_code=201)
def create_user(body: UserCreate, _: dict = Depends(require_admin)):
    uname = body.username.strip()
    if not uname or len(uname) > 50:
        raise HTTPException(400, "Kullanıcı adı boş olamaz.")
    if body.role not in ROLES:
        raise HTTPException(400, "Rol admin veya readonly olmalı.")
    if (p := password_problem(body.password)):
        raise HTTPException(400, p)
    if STORE.get_user(uname):
        raise HTTPException(409, "Bu kullanıcı adı zaten var.")
    u = STORE.create_user(uname, hash_password(body.password), body.role, body.full_name or "")
    return {k: u[k] for k in u if k != "password_hash"}


@app.patch("/api/auth/users/{user_id}")
def toggle_user(user_id: int, me_: dict = Depends(require_admin)):
    u = STORE.get_user(user_id=user_id)
    if not u:
        raise HTTPException(404, "Kullanıcı bulunamadı.")
    if u["id"] == me_["id"]:
        raise HTTPException(400, "Kendi hesabınızı pasif yapamazsınız.")
    if u["is_active"] and u["role"] == "admin" and len(_active_admins()) <= 1:
        raise HTTPException(400, "Son aktif admin pasif yapılamaz.")
    u = STORE.update_user(user_id, is_active=0 if u["is_active"] else 1)
    return {"id": u["id"], "is_active": bool(u["is_active"])}


@app.put("/api/auth/users/{user_id}")
def edit_user(user_id: int, body: UserEdit, me_: dict = Depends(require_admin)):
    u = STORE.get_user(user_id=user_id)
    if not u:
        raise HTTPException(404, "Kullanıcı bulunamadı.")
    if body.role and body.role not in ROLES:
        raise HTTPException(400, "Rol admin veya readonly olmalı.")
    if body.role == "readonly" and u["role"] == "admin" and len(_active_admins()) <= 1:
        raise HTTPException(400, "Son admin'in rolü değiştirilemez.")
    pw_hash = None
    if body.password:
        if (p := password_problem(body.password)):
            raise HTTPException(400, p)
        pw_hash = hash_password(body.password)
    u = STORE.update_user(user_id, full_name=body.full_name, role=body.role, password_hash=pw_hash)
    return {k: u[k] for k in u if k != "password_hash"}


@app.delete("/api/auth/users/{user_id}", status_code=204)
def delete_user(user_id: int, me_: dict = Depends(require_admin)):
    u = STORE.get_user(user_id=user_id)
    if not u:
        raise HTTPException(404, "Kullanıcı bulunamadı.")
    if u["id"] == me_["id"]:
        raise HTTPException(400, "Kendi hesabınızı silemezsiniz.")
    if u["role"] == "admin" and len(_active_admins()) <= 1 and u["is_active"]:
        raise HTTPException(400, "Son aktif admin silinemez.")
    STORE.delete_user(user_id)


# =================================================================== yardımcılar
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def _session(session_id: Optional[str]) -> Optional[dict]:
    """session_id verilirse o tarama; verilmezse birleşik güncel görünüm."""
    if session_id:
        s = STORE.get_scan(session_id)
        if not s:
            raise HTTPException(404, "Tarama bulunamadı.")
        return s
    return _current_view()


def _findings(scan_id: str) -> list[dict]:
    if scan_id not in _FINDINGS_CACHE:
        if len(_FINDINGS_CACHE) > 12:
            _FINDINGS_CACHE.pop(next(iter(_FINDINGS_CACHE)))
        rows = STORE.findings_of(scan_id)
        if not rows:          # henüz bitmemiş / boş tarama önbelleğe alınmaz
            return rows
        _FINDINGS_CACHE[scan_id] = rows
    return _FINDINGS_CACHE[scan_id]


def _scan_findings(s: dict) -> list[dict]:
    return s["_findings"] if "_findings" in s else _findings(s["id"])


def _is_full(s: dict) -> bool:
    req = s.get("request") or {}
    return (s["status"] == "completed" and not req.get("devices") and not req.get("partitions")
            and all(d["ok"] for d in s.get("devices") or []))


_VIEW_CACHE: dict[tuple, dict] = {}


def _current_view() -> Optional[dict]:
    """Güncel durum: her (cihaz, partition) için onu kapsayan EN SON taramanın sonucu.
    Böylece tek bir müşteriyi yeniden taramak diğer müşterileri ekrandan düşürmez."""
    scans = [x for x in STORE.list_scans(200) if x["status"] in ("completed", "partial")]
    if not scans:
        return None
    if _is_full(scans[0]):
        return scans[0]
    used = []
    for x in scans:
        used.append(x)
        if _is_full(x):
            break
    key = tuple(x["id"] for x in used)
    if key in _VIEW_CACHE:
        return _VIEW_CACHE[key]
    covered: set[tuple[str, str]] = set()
    devs: dict[str, dict] = {}
    findings_, resolved_ = [], []
    for x in used:
        for d in x.get("devices") or []:
            name = d["name"]
            if name not in devs:   # cihaz durumu en yeni taramadan
                devs[name] = {**d, "partitions": [], "protections": [], "asm_policies": []}
            if not d["ok"]:
                continue
            scope = {(name, p) for p in d.get("partitions") or []} | {(name, "(cihaz)")}
            new = scope - covered
            if not new:
                continue
            devs[name]["partitions"] += sorted(p for (_, p) in new if p != "(cihaz)")
            devs[name]["protections"] += [r for r in d.get("protections") or [] if (name, r["partition"]) in new]
            devs[name]["asm_policies"] += [r for r in d.get("asm_policies") or [] if (name, r["partition"]) in new]
            findings_ += [f for f in _findings(x["id"]) if (f["device"], f["partition"]) in new]
            resolved_ += [f for f in (x.get("summary") or {}).get("resolved_items", [])
                          if (f["device"], f["partition"]) in new]
            covered |= new
    latest = used[0]
    devices_ = sorted(devs.values(), key=lambda d: d["name"])
    view = {**latest, "devices": devices_, "_findings": findings_, "merged_from": [x["id"] for x in used],
            "summary": {"resolved_items": resolved_, "resolved": len(resolved_),
                        "devices_ok": sum(1 for d in devices_ if d["ok"]), "devices_total": len(devices_),
                        "partitions": [{"device": d["name"], "partition": p} for d in devices_ for p in d["partitions"]],
                        "total": sum(1 for f in findings_ if not f["suppressed"])}}
    _VIEW_CACHE.clear()
    _VIEW_CACHE[key] = view
    return view


def _enriched(s: dict) -> list[dict]:
    st = STORE.status_map()
    out = []
    for f in _scan_findings(s):
        x = st.get(f["fingerprint"]) or {}
        out.append({**f, "wf_status": x.get("status", "open"), "status_comment": x.get("comment"),
                    "assigned_to": x.get("assigned_to"), "status_updated_by": x.get("updated_by"),
                    "status_updated_at": x.get("updated_at"), "is_rule_changed": bool(x.get("is_changed")),
                    "rule_changed_at": x.get("changed_at")})
    return out


def _is_open(f: dict) -> bool:
    return not f["suppressed"] and f["wf_status"] != "resolved"


def _scan_brief(s: dict) -> dict:
    summ = s.get("summary") or {}
    return {"id": s["id"], "started_at": s["started_at"], "finished_at": s["finished_at"],
            "triggered_by": s.get("triggered_by") or "cli", "status": s["status"], "error": s.get("error"),
            "request": s.get("request") or {}, "devices_ok": summ.get("devices_ok"),
            "devices_total": summ.get("devices_total"), "total_findings": summ.get("total"),
            "by_severity": summ.get("by_severity"), "new": summ.get("new"), "closed": summ.get("resolved"),
            "partitions": len(summ.get("partitions") or [])}


# =================================================================== tarama
class ScanRequest(BaseModel):
    device_ids: Optional[list[str]] = None   # None = tüm cihazlar
    partitions: Optional[str] = None         # "P_ACME*, P_BETA_BANK" (opsiyonel)


@app.get("/api/connectors")
def connectors(_: dict = Depends(current_user)):
    """Config'deki cihazlar (şifresiz)."""
    return [{"id": d["name"], "label": d["name"], "host": d.get("host", "mock"), "mock": bool(d.get("mock"))}
            for d in CFG.devices]


def _run_scan(scan_id: str, devices: list[str] | None, partitions: list[str] | None, user: str):
    prog = PROGRESS[scan_id]

    def cb(dev, state, info):
        prog["devices"][dev] = {"state": state, **info}
    try:
        Scanner(CFG, STORE).run(devices=devices, partitions=partitions, scan_id=scan_id,
                                triggered_by=user, progress=cb)
    except Exception as e:  # beklenmeyen hata taramayı 'running'de bırakmasın
        log.exception("Tarama hatası")
        STORE.fail_scan(scan_id, f"Beklenmeyen hata: {e}")
    finally:
        _scan_lock.release()


@app.post("/api/scan")
def trigger_scan(body: ScanRequest = ScanRequest(), user: dict = Depends(require_admin)):
    names = {d["name"] for d in CFG.devices}
    devices = body.device_ids or None
    if devices:
        unknown = set(devices) - names
        if unknown:
            raise HTTPException(400, f"Tanımsız cihaz: {', '.join(sorted(unknown))}")
    parts = [p.strip() for p in (body.partitions or "").replace(";", ",").split(",") if p.strip()] or None
    if not _scan_lock.acquire(blocking=False):
        running = STORE.running_scan()
        return {"session_id": running["id"] if running else None, "status": "running", "already_running": True}
    scan_id = Scanner.new_scan_id()
    PROGRESS[scan_id] = {"devices": {}}
    STORE.start_scan(scan_id, datetime.now(timezone.utc), user["username"],
                     {"devices": devices, "partitions": parts})
    threading.Thread(target=_run_scan, args=(scan_id, devices, parts, user["username"]), daemon=True).start()
    return {"session_id": scan_id, "status": "running"}


@app.get("/api/scan/status")
def scan_status(_: dict = Depends(current_user)):
    running = STORE.running_scan()
    if running:
        return {"running": True, "scan": _scan_brief(running),
                "progress": PROGRESS.get(running["id"], {}).get("devices", {})}
    last = STORE.list_scans(1)
    return {"running": False, "scan": _scan_brief(last[0]) if last else None,
            "progress": PROGRESS.get(last[0]["id"], {}).get("devices", {}) if last else {}}


@app.get("/api/scan/history")
def scan_history(limit: int = Query(20, ge=1, le=200), _: dict = Depends(current_user)):
    return [_scan_brief(s) for s in STORE.list_scans(limit)]


# =================================================================== görünüm
@app.get("/api/summary")
def summary(session_id: Optional[str] = None, _: dict = Depends(current_user)):
    s = _session(session_id)
    running = STORE.running_scan() is not None
    if not s:
        return {"total_findings": 0, "by_severity": {k: 0 for k in SEVERITIES}, "last_scan": None,
                "session_id": None, "scan_running": running, "resolved_count": 0,
                "resolved_changed_count": 0, "new": 0, "suppressed": 0, "closed": 0}
    fs = _enriched(s)
    open_ = [f for f in fs if _is_open(f)]
    resolved = [f for f in fs if f["wf_status"] == "resolved" and not f["suppressed"]]
    summ = s.get("summary") or {}
    return {
        "session_id": s["id"], "last_scan": s["finished_at"], "scan_status": s["status"],
        "scan_running": running, "triggered_by": s.get("triggered_by"),
        "total_findings": len(open_),
        "by_severity": {k: sum(1 for f in open_ if f["severity"] == k) for k in SEVERITIES},
        "new": sum(1 for f in open_ if f["status"] == "NEW"),
        "resolved_count": len(resolved),
        "resolved_changed_count": sum(1 for f in resolved if f["is_rule_changed"]),
        "suppressed": sum(1 for f in fs if f["suppressed"]),
        "by_status": {k: sum(1 for f in fs if not f["suppressed"] and f["wf_status"] == k) for k in WORKFLOW_STATUSES},
        "customers_affected": len({(f["device"], f["partition"]) for f in open_ if f["partition"] != "(cihaz)"}),
        "closed": summ.get("resolved", 0),
        "devices_ok": summ.get("devices_ok"), "devices_total": summ.get("devices_total"),
        "partitions": sum(1 for p in summ.get("partitions") or [] if p["partition"] != "(cihaz)"),
        "merged_from": len(s.get("merged_from") or []) or 1,
    }


@app.get("/api/devices")
def devices(session_id: Optional[str] = None, _: dict = Depends(current_user)):
    """Cihaz → partition ağacı, açık bulgu sayılarıyla (sol menü)."""
    s = _session(session_id)
    if not s:
        return []
    customers = {p["partition"]: p.get("customer") for p in (s.get("summary") or {}).get("partitions", [])}
    tree: dict[str, dict] = {}
    for d in s.get("devices") or []:
        tree[d["name"]] = {"id": d["name"], "host": d["host"], "version": d.get("version"), "ok": d["ok"],
                           "error": d.get("error"), "stats": d.get("stats") or {},
                           "duration_sec": d.get("duration_sec"),
                           "findings": {k: 0 for k in SEVERITIES}, "partitions": {}}
        for p in d.get("partitions") or []:
            tree[d["name"]]["partitions"][p] = {"name": p, "customer": customers.get(p) or CFG.customer_of(p),
                                                "findings": {k: 0 for k in SEVERITIES}}
    for f in _enriched(s):
        if not _is_open(f) or f["device"] not in tree:
            continue
        dev = tree[f["device"]]
        dev["findings"][f["severity"]] += 1
        p = dev["partitions"].setdefault(f["partition"], {"name": f["partition"], "customer": f["customer"],
                                                         "findings": {k: 0 for k in SEVERITIES}})
        p["findings"][f["severity"]] += 1
    out = []
    for dev in tree.values():
        parts = list(dev["partitions"].values())
        for p in parts:
            p["total"] = sum(p["findings"].values())
            p["score"] = sum(SEVERITY_WEIGHT[k] * v for k, v in p["findings"].items())
        parts.sort(key=lambda p: (p["name"] != "(cihaz)", -p["score"], p["name"]))
        dev["partitions"] = parts
        dev["total"] = sum(dev["findings"].values())
        out.append(dev)
    return sorted(out, key=lambda d: d["id"])


@app.get("/api/partitions")
def partitions(session_id: Optional[str] = None, _: dict = Depends(current_user)):
    """Partition / müşteri risk sıralaması (açık bulgulara göre)."""
    rows = []
    for dev in devices(session_id, _):
        for p in dev["partitions"]:
            if p["name"] == "(cihaz)":
                continue
            rows.append({"device": dev["id"], "partition": p["name"], "customer": p["customer"],
                         "score": p["score"], "total": p["total"], **p["findings"]})
    return sorted(rows, key=lambda r: (-r["score"], r["device"], r["partition"]))


@app.get("/api/findings/check-names")
def check_names(session_id: Optional[str] = None, _: dict = Depends(current_user)):
    s = _session(session_id)
    if not s:
        return []
    cnt: dict[str, dict] = {}
    for f in _scan_findings(s):
        c = cnt.setdefault(f["check_id"], {"id": f["check_id"], "title": f["title"],
                                            "category": f["category"], "count": 0})
        c["count"] += 1
    return sorted(cnt.values(), key=lambda c: c["id"])


@app.get("/api/findings")
def findings(device: Optional[str] = None, partition: Optional[str] = None,
             severity: Optional[str] = None, category: Optional[str] = None,
             check_id: Optional[str] = None, status: Optional[str] = None,
             search: Optional[str] = None, changed_only: bool = False,
             session_id: Optional[str] = None,
             page: int = Query(1, ge=1), limit: int = Query(500, ge=1, le=5000),
             _: dict = Depends(current_user)):
    """status: all (varsayılan: açık iş = çözüldü/istisnalı hariç) | open | acknowledged | in_progress |
    resolved | new | suppressed | fixed (son taramada kaybolan = düzeltilmiş)"""
    s = _session(session_id)
    if not s:
        return {"total": 0, "page": page, "limit": limit, "findings": []}
    if status == "fixed":
        rows = [{**f, "wf_status": "fixed"} for f in (s.get("summary") or {}).get("resolved_items", [])]
    else:
        rows = _enriched(s)
        if status in WORKFLOW_STATUSES:
            rows = [f for f in rows if f["wf_status"] == status and not f["suppressed"]]
        elif status == "suppressed":
            rows = [f for f in rows if f["suppressed"]]
        elif status == "new":
            rows = [f for f in rows if _is_open(f) and f["status"] == "NEW"]
        else:
            rows = [f for f in rows if _is_open(f)]
    if device and device != "all":
        rows = [f for f in rows if f["device"] == device]
    if partition and partition != "all":
        rows = [f for f in rows if f["partition"] == partition]
    if severity and severity != "all":
        sevs = {x.strip().upper() for x in severity.split(",") if x.strip()}
        rows = [f for f in rows if f["severity"] in sevs]
    if category and category != "all":
        rows = [f for f in rows if f["category"] == category]
    if check_id and check_id != "all":
        rows = [f for f in rows if f["check_id"] == check_id]
    if changed_only:
        rows = [f for f in rows if f.get("is_rule_changed")]
    if search:
        q = search.lower()
        rows = [f for f in rows if q in " ".join(str(f.get(k, "")) for k in
                ("object_name", "detail", "customer", "partition", "title", "check_id", "device")).lower()]
    rows.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["device"], f["partition"], f["check_id"]))
    total = len(rows)
    rows = rows[(page - 1) * limit: page * limit]
    return {"total": total, "page": page, "limit": limit, "session_id": s["id"], "findings": rows}


class StatusUpdate(BaseModel):
    status: str
    comment: Optional[str] = None
    assigned_to: Optional[str] = None


@app.patch("/api/findings/{fingerprint}/status")
def update_status(fingerprint: str, body: StatusUpdate, user: dict = Depends(require_admin)):
    if body.status not in WORKFLOW_STATUSES:
        raise HTTPException(400, f"Geçersiz durum. Geçerli değerler: {', '.join(WORKFLOW_STATUSES)}")
    view = _current_view()
    finding = next((f for f in _scan_findings(view) if f["fingerprint"] == fingerprint), None) if view else None
    st = STORE.set_status(fingerprint, body.status, comment=body.comment, assigned_to=body.assigned_to,
                          user=user["username"], finding=finding)
    return {"fingerprint": fingerprint, "status": st["status"], "updated_by": st["updated_by"]}


# =================================================================== DoS / Bot envanteri
def _protection_rows(s: dict) -> list[dict]:
    return [r for d in s.get("devices") or [] for r in d.get("protections") or []]


@app.get("/api/protections")
def protections(kind: str = Query("dos", pattern="^(dos|bot)$"), show: str = "used",
                device: Optional[str] = None, partition: Optional[str] = None,
                mode: Optional[str] = None, search: Optional[str] = None,
                session_id: Optional[str] = None, _: dict = Depends(current_user)):
    """kind: dos | bot · show: used (kullananlar) | unused (kullanmayan, koruma beklenen HTTP VS) | all"""
    s = _session(session_id)
    if not s:
        return {"stats": {"eligible": 0, "used": 0, "unused": 0, "by_mode": {}}, "rows": []}
    rows = _protection_rows(s)
    if device and device != "all":
        rows = [r for r in rows if r["device"] == device]
    if partition and partition != "all":
        rows = [r for r in rows if r["partition"] == partition]
    used = [r for r in rows if r[kind]]
    unused = [r for r in rows if not r[kind] and r["eligible"]]
    by_mode: dict[str, int] = {}
    for r in used:
        by_mode[r[kind]["mode"]] = by_mode.get(r[kind]["mode"], 0) + 1
    stats = {"eligible": len([r for r in rows if r["eligible"]]), "used": len(used), "unused": len(unused),
             "covered": len([r for r in used if r["eligible"]]),
             "used_total": len(used), "by_mode": by_mode,
             "customers_used": len({(r["device"], r["partition"]) for r in used})}
    out = used if show == "used" else unused if show == "unused" else used + unused
    if mode and mode != "all":
        out = [r for r in out if r[kind] and r[kind]["mode"] == mode]
    if search:
        q = search.lower()
        out = [r for r in out if q in " ".join(str(r.get(k) or "") for k in
               ("virtual", "partition", "customer", "destination", "device")).lower()
               + " " + ((r[kind] or {}).get("profile") or "").lower()]
    out.sort(key=lambda r: (r["device"], r["partition"], r["virtual"]))
    return {"stats": stats, "rows": out}


# =================================================================== ASM policy envanteri
def _policy_rows(s: dict) -> list[dict]:
    """Policy envanteri + policy'ye ait açık bulgular (WAF-001 transparent süresi dahil)."""
    rows = [{**r, "device_host": d.get("host") or r.get("device_host")}   # IP: config'deki host
            for d in s.get("devices") or [] for r in d.get("asm_policies") or []]
    by_obj: dict[tuple, list] = {}
    for f in _enriched(s):
        if _is_open(f) and f["object_type"] in ("asm-policy", "signature-set"):
            base = f["object_name"].split(" :: ")[0]
            by_obj.setdefault((f["device"], base), []).append(f)
    for r in rows:
        fs = by_obj.get((r["device"], r["full_path"]), [])
        r["findings"] = {k: sum(1 for f in fs if f["severity"] == k) for k in SEVERITIES}
        r["findings_total"] = len(fs)
        tr = next((f for f in fs if f["check_id"] == "WAF-001"), None)
        r["transparent_days"] = (tr or {}).get("evidence", {}).get("days_transparent")
    return rows


@app.get("/api/policies")
def policies(mode: Optional[str] = None, device: Optional[str] = None, partition: Optional[str] = None,
             vs: str = "all", status: str = "all", search: Optional[str] = None,
             session_id: Optional[str] = None, _: dict = Depends(current_user)):
    """mode: blocking | transparent · vs: attached | orphan · status: inactive | modified | findings"""
    s = _session(session_id)
    if not s:
        return {"stats": {"total": 0, "by_mode": {}, "by_device": [], "attached": 0, "orphan": 0,
                          "inactive": 0, "modified": 0}, "rows": []}
    rows = _policy_rows(s)
    if partition and partition != "all":
        rows = [r for r in rows if r["partition"] == partition]
    scoped = [r for r in rows if not device or device == "all" or r["device"] == device]
    by_dev: dict[str, dict] = {}
    for r in rows:   # cihaz filtresi seçenekleri: cihaz filtresinden bağımsız sayılır
        d = by_dev.setdefault(r["device"], {"device": r["device"], "host": r["device_host"],
                                             "total": 0, "blocking": 0, "transparent": 0})
        d["total"] += 1
        if r["mode"] in ("blocking", "transparent"):
            d[r["mode"]] += 1
    stats = {"total": len(scoped),
             "by_mode": {m: sum(1 for r in scoped if r["mode"] == m) for m in sorted({r["mode"] for r in scoped})},
             "by_device": sorted(by_dev.values(), key=lambda d: d["device"]),
             "attached": sum(1 for r in scoped if r["virtual_servers"]),
             "orphan": sum(1 for r in scoped if not r["virtual_servers"]),
             "inactive": sum(1 for r in scoped if not r["active"]),
             "modified": sum(1 for r in scoped if r["modified"]),
             "virtual_servers": sum(len(r["virtual_servers"]) for r in scoped),
             "customers": len({(r["device"], r["partition"]) for r in scoped})}
    out = scoped
    if mode and mode != "all":
        out = [r for r in out if r["mode"] == mode]
    if vs == "attached":
        out = [r for r in out if r["virtual_servers"]]
    elif vs == "orphan":
        out = [r for r in out if not r["virtual_servers"]]
    if status == "inactive":
        out = [r for r in out if not r["active"]]
    elif status == "modified":
        out = [r for r in out if r["modified"]]
    elif status == "findings":
        out = [r for r in out if r["findings_total"]]
    if search:
        q = search.lower()
        out = [r for r in out if q in " ".join([r["full_path"], r["customer"] or "", r["device"], r["device_host"] or ""]
                                               + [v["name"] + " " + v["destination"] for v in r["virtual_servers"]]).lower()]
    out.sort(key=lambda r: (r["mode"] != "transparent", -(r["transparent_days"] or 0), r["device"], r["full_path"]))
    return {"stats": stats, "rows": out}


@app.get("/api/checks")
def checks(_: dict = Depends(current_user)):
    return catalog()


# =================================================================== rapor
WF_LABEL = {"open": "Açık", "acknowledged": "Onaylandı", "in_progress": "İşlemde", "resolved": "Çözüldü"}
MEDIA = {"html": "text/html", "json": "application/json", "csv": "text/csv",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


def _report(s: dict) -> dict:
    summ = dict(s["summary"] or {})
    resolved = summ.pop("resolved_items", [])
    fs = [{**f, "workflow_status": WF_LABEL.get(f["wf_status"], f["wf_status"])} for f in _enriched(s)]
    sid = s["id"] + ("-guncel" if len(s.get("merged_from") or []) > 1 else "")
    return {"scan_id": sid, "status": s["status"], "started_at": s["started_at"],
            "finished_at": s["finished_at"], "summary": summ, "devices": s["devices"] or [],
            "findings": fs, "resolved": resolved, "catalog": catalog(), "protections": _protection_rows(s),
            "asm_policies": _policy_rows(s)}


@app.get("/api/report/{fmt}")
def report(fmt: str, session_id: Optional[str] = None, _: dict = Depends(current_user)):
    if fmt not in MEDIA:
        raise HTTPException(400, "Format: html | xlsx | csv | json")
    s = _session(session_id)
    if not s or s["status"] == "running":
        raise HTTPException(404, "Raporlanacak tamamlanmış tarama yok.")
    path = write_all(_report(s), CFG.output_dir, [fmt])[fmt]
    if fmt == "html":
        return HTMLResponse(Path(path).read_text(encoding="utf-8"))
    return FileResponse(path, media_type=MEDIA[fmt], filename=os.path.basename(path))


# =================================================================== diğer
@app.get("/api/health")
def health():
    return {"status": "ok", "devices": [d["name"] for d in CFG.devices], "scan_running": _scan_lock.locked()}


@app.get("/", response_class=HTMLResponse)
def frontend():
    return HTMLResponse((WEB_DIR / "index.html").read_text(encoding="utf-8"))

