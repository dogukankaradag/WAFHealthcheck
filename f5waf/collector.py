"""Cihazdan konfigürasyon + durum verisini toplayan katman.

Her cihaz için LTM/ASM koleksiyonları bir kez çekilir, partition bazında gruplanır.
Policy'ye özel alt kaynaklar (signature-sets, blocking-settings, vb.) paralel çekilir.
"""
from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .client import F5Client, F5Error

log = logging.getLogger(__name__)

ASM = "/mgmt/tm/asm/policies"


def parse_ts(value: Any) -> datetime | None:
    """ASM zaman damgaları: ISO string, microsaniye int ya da epoch sn."""
    if value in (None, "", 0):
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
            v = int(value)
            if v > 10**14:      # mikro saniye
                v //= 1_000_000
            elif v > 10**11:    # mili saniye
                v //= 1000
            return datetime.fromtimestamp(v, tz=timezone.utc)
        s = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OSError):
        return None


def partition_of(full_path: str) -> str:
    m = re.match(r"^/([^/]+)/", full_path or "")
    return m.group(1) if m else "Common"


@dataclass
class PolicyData:
    raw: dict
    general: dict = field(default_factory=dict)
    policy_builder: dict = field(default_factory=dict)
    signature_settings: dict = field(default_factory=dict)
    signature_sets: list[dict] = field(default_factory=list)
    violations: list[dict] = field(default_factory=list)
    staged_signatures: int | None = None
    disabled_signatures: int | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def full_path(self) -> str:
        return self.raw.get("fullPath") or f"/{self.raw.get('partition', 'Common')}/{self.raw.get('name')}"


@dataclass
class DeviceSnapshot:
    name: str
    host: str
    collected_at: datetime
    version: str = ""
    partitions: list[str] = field(default_factory=list)
    virtuals: list[dict] = field(default_factory=list)
    virtual_stats: dict[str, dict] = field(default_factory=dict)
    pools: list[dict] = field(default_factory=list)
    pool_stats: dict[str, dict] = field(default_factory=dict)
    http_profiles: set[str] = field(default_factory=set)
    clientssl_profiles: list[dict] = field(default_factory=list)
    certs: list[dict] = field(default_factory=list)
    policies: list[PolicyData] = field(default_factory=list)
    sync_status: str = ""
    failover_status: str = ""
    signature_update: datetime | None = None
    signature_update_name: str = ""
    warnings: list[str] = field(default_factory=list)

    def by_partition(self, items: list[dict]) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for it in items:
            p = it.get("partition") or partition_of(it.get("fullPath", ""))
            out.setdefault(p, []).append(it)
        return out


class Collector:
    def __init__(self, client: F5Client, name: str, policy_workers: int = 4,
                 partition_filter=lambda p: True):
        self.c = client
        self.name = name
        self.policy_workers = policy_workers
        self.pf = partition_filter

    def _safe(self, snap: DeviceSnapshot, label: str, fn, default):
        try:
            return fn()
        except F5Error as e:
            snap.warnings.append(f"{label}: {e}")
            log.warning("%s %s: %s", self.name, label, e)
            return default

    def _keep(self, it: dict) -> bool:
        return self.pf(it.get("partition") or partition_of(it.get("fullPath", "")))

    def collect(self) -> DeviceSnapshot:
        c = self.c
        snap = DeviceSnapshot(self.name, c.host, datetime.now(timezone.utc))

        ver = self._safe(snap, "version", lambda: c.get("/mgmt/tm/sys/version"), {})
        for ent in (ver.get("entries") or {}).values():
            e = ent.get("nestedStats", {}).get("entries", {})
            snap.version = e.get("Version", {}).get("description", "")

        parts = self._safe(snap, "partitions", lambda: c.get_items("/mgmt/tm/auth/partition"), [])
        snap.partitions = sorted(p["name"] for p in parts if self.pf(p["name"]))

        snap.virtuals = [v for v in self._safe(
            snap, "virtuals",
            lambda: c.get_items("/mgmt/tm/ltm/virtual", {"expandSubcollections": "true"}), [])
            if self._keep(v)]
        snap.virtual_stats = self._safe(snap, "virtual stats", lambda: c.get_stats("/mgmt/tm/ltm/virtual/stats"), {})
        snap.pools = [p for p in self._safe(
            snap, "pools",
            lambda: c.get_items("/mgmt/tm/ltm/pool", {"expandSubcollections": "true"}), [])
            if self._keep(p)]
        snap.pool_stats = self._safe(snap, "pool stats", lambda: c.get_stats("/mgmt/tm/ltm/pool/stats"), {})
        snap.http_profiles = {p["fullPath"] for p in self._safe(
            snap, "http profiles", lambda: c.get_items("/mgmt/tm/ltm/profile/http"), [])}
        snap.clientssl_profiles = self._safe(
            snap, "client-ssl", lambda: c.get_items("/mgmt/tm/ltm/profile/client-ssl"), [])
        snap.certs = [x for x in self._safe(
            snap, "certs", lambda: c.get_items("/mgmt/tm/sys/file/ssl-cert"), []) if self._keep(x)]

        sync = self._safe(snap, "sync-status", lambda: c.get_stats("/mgmt/tm/cm/sync-status"), {})
        for v in sync.values():
            snap.sync_status = v.get("status") or snap.sync_status
        fo = self._safe(snap, "failover-status", lambda: c.get_stats("/mgmt/tm/cm/failover-status"), {})
        for v in fo.values():
            snap.failover_status = v.get("status") or snap.failover_status

        self._collect_signature_update(snap)

        policies = [p for p in self._safe(snap, "asm policies", lambda: c.get_items(ASM), []) if self._keep(p)]
        with ThreadPoolExecutor(max_workers=self.policy_workers) as ex:
            snap.policies = list(ex.map(self._collect_policy, policies))
        return snap

    def _collect_signature_update(self, snap: DeviceSnapshot) -> None:
        """Yüklü en güncel Attack Signature (ASU) paketinin tarihi."""
        items = self._safe(snap, "asu", lambda: self.c.get_items(
            "/mgmt/tm/live-update/asm-attack-signatures/installations", allow_404=True), [])
        best: tuple[datetime, str] | None = None
        for it in items:
            status = str(it.get("status", "")).lower()
            if status and "install" not in status and "complete" not in status and "current" not in status:
                continue
            name = it.get("filename") or it.get("name") or it.get("id", "")
            ts = None
            m = re.search(r"(20\d{6})_?(\d{6})?", name)
            if m:
                try:
                    ts = datetime.strptime(m.group(1) + (m.group(2) or "000000"), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    ts = None
            ts = ts or parse_ts(it.get("installDateTime") or it.get("lastUpdateMicros"))
            if ts and (best is None or ts > best[0]):
                best = (ts, name)
        if best:
            snap.signature_update, snap.signature_update_name = best

    def _collect_policy(self, raw: dict) -> PolicyData:
        pd = PolicyData(raw=raw)
        pid = raw.get("id")
        base = f"{ASM}/{pid}"

        def grab(label, fn, default):
            try:
                return fn()
            except F5Error as e:
                pd.errors.append(f"{label}: {e}")
                return default

        pd.general = grab("general", lambda: self.c.get(f"{base}/general", allow_404=True), {})
        pd.policy_builder = grab("policy-builder", lambda: self.c.get(f"{base}/policy-builder", allow_404=True), {})
        pd.signature_settings = grab("signature-settings",
                                     lambda: self.c.get(f"{base}/signature-settings", allow_404=True), {})
        pd.signature_sets = grab("signature-sets", lambda: self.c.get_items(
            f"{base}/signature-sets", {"$expand": "signatureSetReference"}, allow_404=True), [])
        pd.violations = grab("violations", lambda: self.c.get_items(
            f"{base}/blocking-settings/violations", allow_404=True), [])
        pd.staged_signatures = grab("staged", lambda: self.c.count(
            f"{base}/signatures", "performStaging eq true"), None)
        pd.disabled_signatures = grab("disabled", lambda: self.c.count(
            f"{base}/signatures", "enabled eq false"), None)
        return pd
