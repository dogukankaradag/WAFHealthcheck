"""Veri modelleri ve yapılandırma yükleyici."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from typing import Any

import yaml

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    category: str
    device: str
    partition: str
    object_type: str
    object_name: str
    detail: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    customer: str = ""
    status: str = "NEW"          # NEW | PERSISTENT
    first_seen: str = ""
    suppressed: bool = False
    suppress_reason: str = ""

    @property
    def fingerprint(self) -> str:
        key = f"{self.check_id}|{self.device}|{self.partition}|{self.object_name}"
        return hashlib.sha1(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class DeviceResult:
    name: str
    host: str
    ok: bool = True
    error: str = ""
    version: str = ""
    partitions: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    duration_sec: float = 0.0


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


DEFAULT_THRESHOLDS = {
    "transparent_max_days": 14,         # transparent modda bu süreyi aşan policy -> HIGH
    "transparent_critical_days": 60,    # bu süreyi aşan -> CRITICAL
    "staging_max_days": 7,              # enforcement readiness + bu süre sonrası staging'de kalan imzalar
    "staging_min_signatures": 1,
    "disabled_signatures_max": 50,      # bu sayının üstünde devre dışı imza -> MEDIUM
    "signature_update_max_days": 30,    # ASU (attack signature update) yaşı
    "cert_expiry_warn_days": 60,
    "cert_expiry_high_days": 30,
    "pool_partial_down_ratio": 0.5,     # üyelerin bu oranından fazlası down -> MEDIUM
}

DEFAULT_CRITICAL_VIOLATIONS = [
    "Attack signature detected",
    "Evasion technique detected",
    "HTTP protocol compliance failed",
    "Illegal meta character in value",
    "Illegal file type",
    "Illegal method",
    "Malformed JSON data",
    "Malformed XML data",
    "Threat Campaign detected",
    "Access from malicious IP address",
    "IP is blacklisted",
    "Illegal request length",
]


class Config:
    def __init__(self, raw: dict):
        raw = _expand_env(raw or {})
        self.raw = raw
        self.devices: list[dict] = raw.get("devices", [])
        defaults = raw.get("defaults", {})
        for d in self.devices:
            for k, v in defaults.items():
                d.setdefault(k, v)
        scan = raw.get("scan", {})
        self.include_partitions: list[str] = scan.get("include_partitions", ["*"])
        self.exclude_partitions: list[str] = scan.get("exclude_partitions", [])
        self.device_workers: int = int(scan.get("device_workers", 3))
        self.policy_workers: int = int(scan.get("policy_workers", 4))
        self.disabled_checks: list[str] = scan.get("disabled_checks", [])
        self.only_waf_partitions: bool = bool(scan.get("only_waf_partitions", False))
        # LTM-003: WAF'sız olması beklenen portlar (80 = HTTPS redirect VS'leri)
        self.no_waf_exempt_ports: list[int] = scan.get("no_waf_exempt_ports", [80])
        self.no_waf_include_non_http: bool = bool(scan.get("no_waf_include_non_http", True))
        self.thresholds = {**DEFAULT_THRESHOLDS, **raw.get("thresholds", {})}
        self.partition_overrides: dict[str, dict] = raw.get("partition_overrides", {})
        self.critical_violations: list[str] = raw.get("critical_violations", DEFAULT_CRITICAL_VIOLATIONS)
        self.customers: dict[str, str] = raw.get("customers", {})
        self.suppressions: list[dict] = raw.get("suppressions", [])
        out = raw.get("output", {})
        self.output_dir: str = out.get("dir", "reports")
        self.formats: list[str] = out.get("formats", ["html", "xlsx", "json", "csv"])
        self.state_db: str = raw.get("state_db", "state/waf_healthcheck.db")
        api = raw.get("api", {})
        self.api_keys: list[str] = [k for k in api.get("keys", []) if k]

    @classmethod
    def load(cls, path: str) -> "Config":
        with open(path, encoding="utf-8") as f:
            return cls(yaml.safe_load(f))

    # ------------------------------------------------------------ helpers
    def partition_selected(self, partition: str) -> bool:
        inc = any(fnmatch.fnmatch(partition, p) for p in self.include_partitions)
        exc = any(fnmatch.fnmatch(partition, p) for p in self.exclude_partitions)
        return inc and not exc

    def threshold(self, name: str, partition: str) -> Any:
        for pattern, ov in self.partition_overrides.items():
            if fnmatch.fnmatch(partition, pattern) and name in ov:
                return ov[name]
        return self.thresholds[name]

    def customer_of(self, partition: str) -> str:
        return self.customers.get(partition, partition)

    def match_suppression(self, f: Finding) -> str | None:
        today = date.today()
        for s in self.suppressions:
            until = s.get("until")
            if until:
                until_d = until if isinstance(until, date) else datetime.strptime(str(until), "%Y-%m-%d").date()
                if until_d < today:
                    continue
            if not fnmatch.fnmatch(f.check_id, s.get("check", "*")):
                continue
            if not fnmatch.fnmatch(f.device, s.get("device", "*")):
                continue
            if not fnmatch.fnmatch(f.partition, s.get("partition", "*")):
                continue
            if not fnmatch.fnmatch(f.object_name, s.get("object", "*")):
                continue
            reason = s.get("reason", "istisna")
            return f"{reason}" + (f" (bitiş: {until})" if until else "")
        return None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
