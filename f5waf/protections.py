"""Virtual server bazlı DoS Protection ve Bot Protection envanteri.

Bulgu (finding) değil, envanterdir: hangi VS hangi profili hangi modda kullanıyor, hangisi kullanmıyor.

- DoS Protection : /mgmt/tm/security/dos/profile  (VS'e profil olarak bağlanır)
    application alt koleksiyonu varsa L7 (uygulama) DoS; yoksa yalnızca network/protokol DoS.
    Mod: tpsBased / stressBased / behavioral bloklarındaki 'mode' ya da 'operationMode'.
- Bot Protection : /mgmt/tm/security/bot-defense/profile (v14.1+), alan 'enforcementMode'.
    v14.1 öncesi (legacy) bot defense, DoS profilinin application bloğundaki 'botDefense.mode' ile tutulur.
"""
from __future__ import annotations

from .checks import _profiles, vs_port
from .collector import DeviceSnapshot, partition_of
from .models import Config

_RANK = {"blocking": 3, "transparent": 2, "learning": 1, "off": 0}


def _norm_mode(v) -> str | None:
    if v is None:
        return None
    m = str(v).lower().replace("_", "-")
    if m in ("block", "blocking", "always", "during-attacks", "enabled"):
        return "blocking"
    if m in ("transparent", "monitor", "monitoring", "alarm"):
        return "transparent"
    if m in ("learn-only", "learning"):
        return "learning"
    if m in ("off", "disabled", "none", "false"):
        return "off"
    return m


def _strongest(modes: list[str | None]) -> str:
    ms = [m for m in modes if m]
    return max(ms, key=lambda m: _RANK.get(m, 1)) if ms else "unknown"


def dos_info(path: str, prof: dict) -> dict:
    apps = (prof.get("applicationReference") or {}).get("items") or prof.get("application") or []
    if isinstance(apps, dict):
        apps = [apps]
    detections: dict[str, str] = {}
    legacy_bot = None
    for a in apps:
        for key, label in (("tpsBased", "TPS tabanlı"), ("stressBased", "Stres tabanlı"),
                           ("behavioralDosDetection", "Davranışsal"), ("heavyUrlProtection", "Ağır URL")):
            blk = a.get(key)
            if isinstance(blk, dict):
                m = _norm_mode(blk.get("mode") or blk.get("operationMode"))
                if m:
                    detections[label] = m
        bd = a.get("botDefense")
        if isinstance(bd, dict):
            legacy_bot = _norm_mode(bd.get("mode"))
    kind = "application" if apps else "network"
    mode = _strongest(list(detections.values())) if apps else "network"
    return {"profile": path, "kind": kind, "mode": mode, "detections": detections,
            "legacy_bot": legacy_bot if legacy_bot and legacy_bot != "off" else None}


def bot_info(path: str, prof: dict) -> dict:
    return {"profile": path, "mode": _norm_mode(prof.get("enforcementMode")) or "unknown",
            "template": prof.get("template"), "source": "bot-defense"}


def build_inventory(snap: DeviceSnapshot, cfg: Config) -> list[dict]:
    vs_policy: dict[str, str] = {}
    for p in snap.policies:
        for vs in p.raw.get("virtualServers") or []:
            vs_policy[vs] = p.full_path
    exempt = {int(x) for x in cfg.no_waf_exempt_ports}
    rows = []
    for v in snap.virtuals:
        fp = v["fullPath"]
        part = v.get("partition") or partition_of(fp)
        profs = _profiles(v)
        is_http = any(pr in snap.http_profiles or pr.endswith("/http") for pr in profs)
        port = vs_port(v.get("destination"))
        forwarding = any(v.get(k) for k in ("ipForward", "l2Forward", "reject", "internal"))
        dos = next((dos_info(p, snap.dos_profiles[p]) for p in profs if p in snap.dos_profiles), None)
        bot = next((bot_info(p, snap.bot_profiles[p]) for p in profs if p in snap.bot_profiles), None)
        if not bot and dos and dos.get("legacy_bot"):
            bot = {"profile": dos["profile"], "mode": dos["legacy_bot"], "template": None, "source": "dos-legacy"}
        st = snap.virtual_stats.get(fp, {})
        rows.append({
            "device": snap.name, "partition": part, "customer": cfg.customer_of(part),
            "virtual": fp, "destination": (v.get("destination") or "").rsplit("/", 1)[-1], "port": port,
            "http": is_http, "waf_policy": vs_policy.get(fp),
            "availability": st.get("status.availabilityState"), "enabled": st.get("status.enabledState", "enabled"),
            # DoS/Bot korumasının beklendiği VS: HTTP, yönlendirme portu değil, forwarding değil
            "eligible": bool(is_http and port not in exempt and not forwarding),
            "dos": dos, "bot": bot,
        })
    return rows


def build_policy_inventory(snap: DeviceSnapshot, cfg: Config) -> list[dict]:
    """Cihazdaki tüm ASM (WAF) policy'leri: mod, bağlı VS'ler, son değişiklik, learning, staging."""
    from .collector import parse_ts
    dest = {v["fullPath"]: (v.get("destination") or "").rsplit("/", 1)[-1] for v in snap.virtuals}
    rows = []
    for p in snap.policies:
        raw = p.raw
        part = raw.get("partition") or partition_of(p.full_path)
        changed = parse_ts(raw.get("versionDatetime") or raw.get("lastUpdateMicros"))
        created = parse_ts(raw.get("createdDatetime"))
        rows.append({
            "device": snap.name, "device_host": snap.host.replace("https://", "").replace("mock://", ""),
            "partition": part, "customer": cfg.customer_of(part),
            "name": raw.get("name") or p.full_path.rsplit("/", 1)[-1], "full_path": p.full_path,
            "mode": str(raw.get("enforcementMode") or "unknown").lower(),
            "active": raw.get("active", True) is not False,
            "modified": raw.get("isModified") is True,
            "virtual_servers": [{"name": vs, "destination": dest.get(vs, "")}
                                for vs in raw.get("virtualServers") or []],
            "last_change": changed.isoformat() if changed else None,
            "created": created.isoformat() if created else None,
            "learning_mode": (p.policy_builder or {}).get("learningMode"),
            "staged_signatures": p.staged_signatures,
            "disabled_signatures": p.disabled_signatures,
            "readiness_days": (p.general or {}).get("enforcementReadinessPeriod"),
        })
    return rows
