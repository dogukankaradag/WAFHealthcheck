"""REST API (FastAPI).

  POST /api/scans                      -> taramayı arka planda başlatır
  GET  /api/scans                      -> tarama geçmişi
  GET  /api/scans/{id}                 -> özet + durum
  GET  /api/scans/{id}/findings        -> filtrelenebilir bulgular
  GET  /api/scans/{id}/report.{fmt}    -> html | xlsx | json | csv
  GET  /api/scans/latest/...           -> 'latest' her yerde son tamamlanan tarama yerine geçer
  GET  /api/partitions/{partition}     -> bir müşterinin son durumu
  GET  /api/checks                     -> kontrol kataloğu
  GET  /api/health

Kimlik doğrulama: config.api.keys doluysa `X-API-Key` başlığı zorunludur.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from .checks import catalog
from .models import SEVERITIES, Config
from .reporters import write_all
from .scanner import Scanner
from .state import StateStore

CFG = Config.load(os.environ.get("F5WAF_CONFIG", "config.yaml"))
STORE = StateStore(CFG.state_db)
_scan_lock = threading.Lock()

app = FastAPI(title="F5 WAF Healthcheck API", version="1.0.0")


def auth(x_api_key: Optional[str] = Header(default=None)):
    if CFG.api_keys and x_api_key not in CFG.api_keys:
        raise HTTPException(401, "Geçersiz veya eksik X-API-Key")


class ScanRequest(BaseModel):
    devices: list[str] | None = None
    partitions: list[str] | None = None


def _resolve(scan_id: str) -> dict:
    if scan_id == "latest":
        scans = [s for s in STORE.list_scans(20) if s["status"] in ("completed", "partial")]
        if not scans:
            raise HTTPException(404, "Tamamlanmış tarama yok")
        return scans[0]
    s = STORE.get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Tarama bulunamadı")
    return s


def _report(scan: dict) -> dict:
    summary = dict(scan["summary"] or {})
    resolved = summary.pop("resolved_items", [])
    return {"scan_id": scan["id"], "status": scan["status"], "started_at": scan["started_at"],
            "finished_at": scan["finished_at"], "summary": summary, "devices": scan["devices"] or [],
            "findings": STORE.findings_of(scan["id"]), "resolved": resolved, "catalog": catalog()}


def _run(scan_id: str, req: ScanRequest):
    with _scan_lock:  # aynı anda tek tarama (cihazları yormamak için)
        Scanner(CFG, STORE).run(devices=req.devices, partitions=req.partitions, scan_id=scan_id)


@app.get("/api/health")
def health():
    return {"status": "ok", "devices": [d["name"] for d in CFG.devices], "scan_running": _scan_lock.locked()}


@app.get("/api/checks", dependencies=[Depends(auth)])
def checks():
    return catalog()


@app.post("/api/scans", status_code=202, dependencies=[Depends(auth)])
def start_scan(req: ScanRequest, bg: BackgroundTasks):
    if _scan_lock.locked():
        raise HTTPException(409, "Devam eden bir tarama var")
    unknown = set(req.devices or []) - {d["name"] for d in CFG.devices}
    if unknown:
        raise HTTPException(400, f"Tanımsız cihaz: {', '.join(unknown)}")
    scan_id = Scanner.new_scan_id()
    STORE.start_scan(scan_id, datetime.now(timezone.utc))
    bg.add_task(_run, scan_id, req)
    return {"scan_id": scan_id, "status": "running", "links": {
        "self": f"/api/scans/{scan_id}", "findings": f"/api/scans/{scan_id}/findings",
        "html": f"/api/scans/{scan_id}/report.html"}}


@app.get("/api/scans", dependencies=[Depends(auth)])
def list_scans(limit: int = 20):
    out = []
    for s in STORE.list_scans(limit):
        summ = s.get("summary") or {}
        out.append({"scan_id": s["id"], "status": s["status"], "started_at": s["started_at"],
                    "finished_at": s["finished_at"], "total": summ.get("total"),
                    "by_severity": summ.get("by_severity"), "new": summ.get("new"),
                    "resolved": summ.get("resolved"), "error": s.get("error")})
    return out


@app.get("/api/scans/{scan_id}", dependencies=[Depends(auth)])
def get_scan(scan_id: str):
    s = _resolve(scan_id)
    summ = dict(s.get("summary") or {})
    summ.pop("resolved_items", None)
    return {"scan_id": s["id"], "status": s["status"], "started_at": s["started_at"],
            "finished_at": s["finished_at"], "error": s.get("error"), "summary": summ, "devices": s["devices"]}


@app.get("/api/scans/{scan_id}/findings", dependencies=[Depends(auth)])
def findings(scan_id: str, device: str | None = None, partition: str | None = None,
             severity: list[str] | None = Query(default=None), min_severity: str | None = None,
             check_id: str | None = None, status: str | None = None, include_suppressed: bool = False):
    s = _resolve(scan_id)
    rows = STORE.findings_of(s["id"])
    limit = SEVERITIES.index(min_severity.upper()) if min_severity else None

    def ok(f):
        return ((include_suppressed or not f["suppressed"])
                and (not device or f["device"] == device)
                and (not partition or f["partition"] == partition)
                and (not severity or f["severity"] in [x.upper() for x in severity])
                and (limit is None or SEVERITIES.index(f["severity"]) <= limit)
                and (not check_id or f["check_id"] == check_id)
                and (not status or f["status"] == status.upper()))
    res = [f for f in rows if ok(f)]
    res.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["device"], f["partition"]))
    return {"scan_id": s["id"], "count": len(res), "findings": res}


@app.get("/api/partitions/{partition}", dependencies=[Depends(auth)])
def partition_status(partition: str, device: str | None = None):
    s = _resolve("latest")
    rows = [f for f in STORE.findings_of(s["id"]) if f["partition"] == partition
            and (not device or f["device"] == device) and not f["suppressed"]]
    part = [p for p in (s["summary"] or {}).get("partitions", []) if p["partition"] == partition
            and (not device or p["device"] == device)]
    if not part:
        raise HTTPException(404, "Partition son taramada yok")
    return {"scan_id": s["id"], "partition": part, "findings": rows}


MEDIA = {"html": "text/html", "json": "application/json", "csv": "text/csv",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


@app.get("/api/scans/{scan_id}/report.{fmt}", dependencies=[Depends(auth)])
def report(scan_id: str, fmt: str):
    if fmt not in MEDIA:
        raise HTTPException(400, "fmt: html | xlsx | json | csv")
    s = _resolve(scan_id)
    if s["status"] == "running":
        raise HTTPException(409, "Tarama devam ediyor")
    path = write_all(_report(s), CFG.output_dir, [fmt])[fmt]
    if fmt == "html":
        return HTMLResponse(open(path, encoding="utf-8").read())
    return FileResponse(path, media_type=MEDIA[fmt], filename=os.path.basename(path))
