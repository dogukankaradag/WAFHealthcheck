"""Tarama orkestrasyonu: cihazları paralel tarar, kuralları çalıştırır, durumu kaydeder."""
from __future__ import annotations

import fnmatch
import logging
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .checks import DEVICE_PARTITION, run_checks
from .client import F5Client
from .collector import Collector
from .models import SEVERITIES, SEVERITY_WEIGHT, Config, DeviceResult, Finding
from .state import StateStore

log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    scan_id: str
    started_at: datetime
    finished_at: datetime | None = None
    devices: list[DeviceResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)
    status: str = "completed"

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    def to_report(self) -> dict:
        from .checks import catalog
        return {
            "scan_id": self.scan_id, "status": self.status,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "summary": self.summary(), "devices": [d.__dict__ for d in self.devices],
            "findings": [f.to_dict() for f in self.findings],
            "resolved": self.resolved, "catalog": catalog(),
        }

    def summary(self) -> dict:
        act = self.active
        by_sev = {s: sum(1 for f in act if f.severity == s) for s in SEVERITIES}
        parts: dict[tuple[str, str], dict] = {}
        for f in act:
            key = (f.device, f.partition)
            p = parts.setdefault(key, {"device": f.device, "partition": f.partition, "customer": f.customer,
                                       "score": 0, **{s: 0 for s in SEVERITIES}})
            p[f.severity] += 1
            p["score"] += SEVERITY_WEIGHT[f.severity]
        for d in self.devices:  # temiz partition'ları da listele
            for p in d.partitions:
                parts.setdefault((d.name, p), {"device": d.name, "partition": p, "customer": p,
                                               "score": 0, **{s: 0 for s in SEVERITIES}})
        by_check: dict[str, dict] = {}
        for f in act:
            c = by_check.setdefault(f.check_id, {"check_id": f.check_id, "title": f.title, "count": 0})
            c["count"] += 1
        return {
            "scan_id": self.scan_id,
            "total": len(act),
            "new": sum(1 for f in act if f.status == "NEW"),
            "resolved": len(self.resolved),
            "suppressed": len(self.findings) - len(act),
            "by_severity": by_sev,
            "partitions": sorted(parts.values(), key=lambda x: (-x["score"], x["device"], x["partition"])),
            "by_check": sorted(by_check.values(), key=lambda x: -x["count"]),
            "devices_ok": sum(1 for d in self.devices if d.ok),
            "devices_total": len(self.devices),
        }


def make_client(dev: dict) -> F5Client:
    if dev.get("mock"):
        from .mock import MockClient
        return MockClient(dev["name"], dev.get("mock_profile", dev["name"]))
    verify = dev.get("verify_ssl", True)
    if isinstance(verify, str) and verify.lower() in ("false", "no", "0"):
        verify = False
    return F5Client(dev["host"], dev["username"], dev["password"],
                    login_provider=dev.get("login_provider", "tmos"), verify_ssl=verify,
                    timeout=int(dev.get("timeout", 60)))


class Scanner:
    def __init__(self, cfg: Config, store: StateStore | None = None):
        self.cfg = cfg
        self.store = store or StateStore(cfg.state_db)

    @staticmethod
    def new_scan_id() -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)

    def run(self, devices: list[str] | None = None, partitions: list[str] | None = None,
            scan_id: str | None = None) -> ScanResult:
        scan_id = scan_id or self.new_scan_id()
        res = ScanResult(scan_id, datetime.now(timezone.utc))
        self.store.start_scan(scan_id, res.started_at)

        targets = [d for d in self.cfg.devices if not devices or d["name"] in devices]

        def pfilter(p: str) -> bool:
            if not self.cfg.partition_selected(p):
                return False
            return not partitions or any(fnmatch.fnmatch(p, x) for x in partitions)

        def scan_device(dev: dict) -> tuple[DeviceResult, list[Finding]]:
            dr = DeviceResult(dev["name"], dev.get("host", "mock"))
            t0 = time.time()
            client = None
            try:
                client = make_client(dev)
                snap = Collector(client, dev["name"], self.cfg.policy_workers, pfilter).collect()
                dr.version = snap.version
                dr.partitions = snap.partitions
                dr.stats = {"virtuals": len(snap.virtuals), "pools": len(snap.pools),
                            "policies": len(snap.policies), "certs": len(snap.certs),
                            "warnings": len(snap.warnings)}
                found = run_checks(snap, self.cfg, lambda k: self.store.observe(k, snap.collected_at))
                if snap.warnings and not snap.virtuals and not snap.policies:
                    dr.ok, dr.error = False, snap.warnings[0]
                return dr, found
            except Exception as e:
                log.exception("%s taranamadı", dev["name"])
                dr.ok, dr.error = False, str(e)
                return dr, []
            finally:
                dr.duration_sec = round(time.time() - t0, 1)
                if client is not None and hasattr(client, "logout"):
                    client.logout()

        with ThreadPoolExecutor(max_workers=max(1, self.cfg.device_workers)) as ex:
            futs = [ex.submit(scan_device, d) for d in targets]
            for fut in as_completed(futs):
                dr, found = fut.result()
                res.devices.append(dr)
                res.findings.extend(found)
        res.devices.sort(key=lambda d: d.name)

        # --- istisnalar
        for f in res.findings:
            reason = self.cfg.match_suppression(f)
            if reason:
                f.suppressed, f.suppress_reason = True, reason

        # --- yeni / devam eden / kapanan
        first = self.store.first_seen_map([f.fingerprint for f in res.findings])
        for f in res.findings:
            if f.fingerprint in first:
                f.status, f.first_seen = "PERSISTENT", first[f.fingerprint]
            else:
                f.status, f.first_seen = "NEW", res.started_at.isoformat()

        scope = {d.name: set(d.partitions) | {DEVICE_PARTITION} for d in res.devices if d.ok}
        prev = self.store.previous_scan_id(scan_id)
        if prev:
            current = {f.fingerprint for f in res.findings}
            for old in self.store.findings_of(prev):
                if old["device"] in scope and old["partition"] in scope[old["device"]] \
                        and old["fingerprint"] not in current and not old.get("suppressed"):
                    res.resolved.append(old)

        self.store.prune_observations(scope)
        res.finished_at = datetime.now(timezone.utc)
        res.status = "completed" if all(d.ok for d in res.devices) else (
            "partial" if any(d.ok for d in res.devices) else "failed")
        sev_order = {s: i for i, s in enumerate(SEVERITIES)}
        res.findings.sort(key=lambda f: (f.suppressed, sev_order[f.severity], f.device, f.partition, f.check_id))
        self.store.finish_scan(scan_id, status=res.status,
                               summary={**res.summary(), "resolved_items": res.resolved},
                               devices=[d.__dict__ for d in res.devices],
                               findings=[f.to_dict() for f in res.findings],
                               error="; ".join(f"{d.name}: {d.error}" for d in res.devices if not d.ok))
        return res
