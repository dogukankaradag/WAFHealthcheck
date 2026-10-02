"""Birim + entegrasyon testleri.  Çalıştırma:  python -m pytest -q"""
from __future__ import annotations

import copy
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f5waf.checks import run_checks  # noqa: E402
from f5waf.client import F5Client  # noqa: E402
from f5waf.collector import DeviceSnapshot, PolicyData  # noqa: E402
from f5waf.models import Config  # noqa: E402
from f5waf.scanner import Scanner  # noqa: E402
from f5waf.state import StateStore  # noqa: E402

NOW = datetime.now(timezone.utc)


# ----------------------------------------------------------------- client
class FakeResp:
    def __init__(self, code, data):
        self.status_code, self._d, self.text = code, data, str(data)

    def json(self):
        return self._d


class FakeSession:
    def __init__(self, routes):
        self.routes, self.headers, self.verify, self.calls = routes, {}, True, []

    def post(self, url, json=None, timeout=None):
        return FakeResp(200, {"token": {"token": "T1"}})

    def patch(self, url, json=None, timeout=None):
        return FakeResp(200, {})

    def delete(self, url, timeout=None):
        return FakeResp(200, {})

    def get(self, url, params=None, timeout=None):
        self.calls.append(url)
        r = self.routes[url]
        return r.pop(0) if isinstance(r, list) else r


def test_client_pagination_rewrites_localhost_and_relogins():
    c = F5Client("bigip.lab", "u", "p")
    base = "https://bigip.lab/mgmt/tm/asm/policies"
    c.session = FakeSession({
        base: [FakeResp(401, {}), FakeResp(200, {"items": [{"id": 1}], "nextLink": "https://localhost/mgmt/tm/asm/policies?$skip=1"})],
        f"{base}?$skip=1": FakeResp(200, {"items": [{"id": 2}]}),
    })
    items = c.get_items("/mgmt/tm/asm/policies")
    assert [i["id"] for i in items] == [1, 2]
    assert c.session.headers["X-F5-Auth-Token"] == "T1"


def test_client_stats_flatten():
    c = F5Client("bigip.lab", "u", "p")
    c.session = FakeSession({"https://bigip.lab/mgmt/tm/ltm/virtual/stats": FakeResp(200, {"entries": {
        "https://localhost/mgmt/tm/ltm/virtual/~P_A~vs1/stats": {"nestedStats": {"entries": {
            "tmName": {"description": "/P_A/vs1"},
            "status.availabilityState": {"description": "offline"},
            "clientside.curConns": {"value": 3}}}}}})})
    st = c.get_stats("/mgmt/tm/ltm/virtual/stats")
    assert st["/P_A/vs1"]["status.availabilityState"] == "offline"
    assert st["/P_A/vs1"]["clientside.curConns"] == 3


# ----------------------------------------------------------------- checks
def _policy(mode="blocking", days_since_change=1, vs=("/P_A/vs1",), **kw):
    raw = {"id": "x", "name": "pol", "partition": "P_A", "fullPath": "/P_A/pol", "enforcementMode": mode,
           "active": True, "virtualServers": list(vs),
           "createdDatetime": (NOW - timedelta(days=400)).isoformat(),
           "versionDatetime": (NOW - timedelta(days=days_since_change)).isoformat()}
    pd = PolicyData(raw=raw, general={"enforcementReadinessPeriod": 7}, policy_builder={"learningMode": "manual"},
                    staged_signatures=0, disabled_signatures=0)
    for k, v in kw.items():
        setattr(pd, k, v)
    return pd


def _snap(policies):
    s = DeviceSnapshot("waf01", "h", NOW, partitions=["P_A"])
    s.virtuals = [{"fullPath": "/P_A/vs1", "partition": "P_A", "pool": "/P_A/pool1",
                   "profilesReference": {"items": [{"fullPath": "/Common/http"}]},
                   "securityLogProfiles": ["log"]}]
    s.virtual_stats = {"/P_A/vs1": {"status.availabilityState": "available", "status.enabledState": "enabled"}}
    s.pools = [{"fullPath": "/P_A/pool1", "partition": "P_A", "monitor": "/Common/http",
                "membersReference": {"items": [{"name": "a", "state": "up"}]}}]
    s.http_profiles = {"/Common/http"}
    s.policies = policies
    s.signature_update = NOW - timedelta(days=3)
    s.sync_status = "In Sync"
    return s


def _run(snap, cfg=None, observe=None):
    return run_checks(snap, cfg or Config({}), observe or (lambda k: NOW))


@pytest.mark.parametrize("days,sev", [(3, "MEDIUM"), (20, "HIGH"), (90, "CRITICAL")])
def test_transparent_severity_by_age(days, sev):
    f = [x for x in _run(_snap([_policy("transparent", days)])) if x.check_id == "WAF-001"]
    assert len(f) == 1 and f[0].severity == sev


def test_transparent_uses_observed_history_when_longer():
    # cihazda 2 gün önce değişiklik olmuş ama state DB 30 gündür transparent görüyor
    f = _run(_snap([_policy("transparent", 2)]), observe=lambda k: NOW - timedelta(days=30))
    assert [x.severity for x in f if x.check_id == "WAF-001"] == ["HIGH"]


def test_partition_override_threshold():
    cfg = Config({"partition_overrides": {"P_*": {"transparent_max_days": 45}}})
    f = _run(_snap([_policy("transparent", 20)]), cfg)
    assert [x.severity for x in f if x.check_id == "WAF-001"] == ["MEDIUM"]


def test_clean_policy_has_no_findings():
    assert _run(_snap([_policy()])) == []


def test_signature_set_and_violation_block():
    p = _policy(signature_sets=[{"signatureSetReference": {"name": "SQLi"}, "alarm": True, "block": False}],
                violations=[{"description": "Attack signature detected", "alarm": True, "block": False},
                            {"description": "Illegal URL", "alarm": False, "block": False}])  # kritik listede değil
    f = _run(_snap([p]))
    assert {(x.check_id, x.severity) for x in f} == {("WAF-005", "HIGH"), ("WAF-006", "HIGH")}


def test_staging_old_policy():
    f = _run(_snap([_policy(staged_signatures=40)]))
    assert [x.check_id for x in f] == ["WAF-004"]


def test_http_vs_without_waf_and_no_logging():
    s = _snap([])
    assert [x.check_id for x in _run(s)] == ["LTM-003"]
    s2 = _snap([_policy()])
    s2.virtuals[0]["securityLogProfiles"] = []
    assert [x.check_id for x in _run(s2)] == ["LTM-004"]


@pytest.mark.parametrize("dest,port", [("/P/10.0.0.1:443", 443), ("/P/10.0.0.1%12:80", 80),
                                       ("/P/2001:db8::1.8443", 8443), ("/P/0.0.0.0:any", 0), (None, None)])
def test_vs_port_parse(dest, port):
    from f5waf.checks import vs_port
    assert vs_port(dest) == port


def test_no_waf_vs_excludes_port_80_and_lists_l4():
    s = _snap([_policy()])  # vs1 WAF'lı
    s.virtuals += [
        {"fullPath": "/P_A/vs_80", "partition": "P_A", "destination": "/P_A/10.0.0.1:80",
         "rules": ["/Common/_sys_https_redirect"], "profilesReference": {"items": [{"fullPath": "/Common/http"}]}},
        {"fullPath": "/P_A/vs_8080", "partition": "P_A", "destination": "/P_A/10.0.0.1:8080", "pool": "/P_A/pool1",
         "profilesReference": {"items": [{"fullPath": "/Common/http"}]}},
        {"fullPath": "/P_A/vs_l4", "partition": "P_A", "destination": "/P_A/10.0.0.1:443", "pool": "/P_A/pool1",
         "profilesReference": {"items": [{"fullPath": "/Common/fastL4"}]}}]
    s.virtual_stats["/P_A/vs_80"] = {"status.availabilityState": "unknown"}
    got = {(x.object_name, x.severity) for x in _run(s) if x.check_id in ("LTM-003", "LTM-001")}
    assert got == {("/P_A/vs_8080", "HIGH"), ("/P_A/vs_l4", "MEDIUM")}
    cfg = Config({"scan": {"no_waf_exempt_ports": [], "no_waf_include_non_http": False}})
    got = {x.object_name for x in _run(s, cfg) if x.check_id == "LTM-003"}
    assert got == {"/P_A/vs_80", "/P_A/vs_8080"}


def test_pool_all_down_and_unreadable_policy():
    s = _snap([_policy(errors=["violations: 503"])])
    s.pools[0]["membersReference"]["items"][0]["state"] = "down"
    ids = sorted((x.check_id, x.severity) for x in _run(s))
    assert ids == [("LTM-002", "HIGH"), ("WAF-011", "MEDIUM")]


def test_suppression_and_expiry():
    cfg = Config({"suppressions": [
        {"check": "WAF-001", "partition": "P_A", "reason": "CHG1", "until": "2999-01-01"},
        {"check": "LTM-003", "reason": "eski", "until": "2000-01-01"}]})
    from f5waf.models import Finding
    f1 = Finding("WAF-001", "", "HIGH", "", "waf01", "P_A", "", "/P_A/pol", "", "")
    f2 = Finding("LTM-003", "", "HIGH", "", "waf01", "P_A", "", "/P_A/vs", "", "")
    assert cfg.match_suppression(f1).startswith("CHG1")
    assert cfg.match_suppression(f2) is None


# ------------------------------------------------------- scanner + state
def _mock_cfg(tmp_path):
    return Config({"devices": [{"name": n, "mock": True} for n in ("waf01", "waf02", "waf03")],
                   "scan": {"exclude_partitions": ["Common"]},
                   "state_db": str(tmp_path / "s.db"), "output": {"dir": str(tmp_path / "r")}})


def test_scan_tracks_new_persistent_resolved(tmp_path, monkeypatch):
    cfg = _mock_cfg(tmp_path)
    store = StateStore(cfg.state_db)
    r1 = Scanner(cfg, store).run()
    assert r1.status == "completed" and r1.findings and all(f.status == "NEW" for f in r1.findings)

    # ikinci taramada bir policy'yi düzelt -> kapanan bulgu olmalı
    from f5waf import mock
    orig = mock.MockClient.__init__

    def patched(self, name, profile):
        orig(self, name, profile)
        for p in self.policies:
            p["enforcementMode"] = "blocking"
    monkeypatch.setattr(mock.MockClient, "__init__", patched)
    r2 = Scanner(cfg, store).run()
    assert not [f for f in r2.findings if f.check_id == "WAF-001"]
    assert any(f["check_id"] == "WAF-001" for f in r2.resolved)
    assert all(f.status == "PERSISTENT" for f in r2.findings if f.check_id == "CERT-001")


def test_partial_scan_scope(tmp_path):
    cfg = _mock_cfg(tmp_path)
    store = StateStore(cfg.state_db)
    Scanner(cfg, store).run()
    r = Scanner(cfg, store).run(devices=["waf01"], partitions=["P_ACME"])
    assert {f.partition for f in r.findings} <= {"P_ACME", "(cihaz)"}
    assert r.resolved == []  # taranmayan partition'lar "kapandı" sayılmamalı


def test_reports_written(tmp_path):
    from f5waf.reporters import write_all
    cfg = _mock_cfg(tmp_path)
    rep = Scanner(cfg).run().to_report()
    files = write_all(rep, str(tmp_path / "out"), ["html", "xlsx", "json", "csv"])
    for p in files.values():
        assert os.path.getsize(p) > 1000


# -------------------------------------------------------------------- api
def test_api(tmp_path, monkeypatch):
    import yaml
    cfgp = tmp_path / "c.yaml"
    cfgp.write_text(yaml.safe_dump({"devices": [{"name": "waf01", "mock": True}],
                                    "state_db": str(tmp_path / "a.db"), "output": {"dir": str(tmp_path / "r")},
                                    "api": {"keys": ["k1"]}}))
    monkeypatch.setenv("F5WAF_CONFIG", str(cfgp))
    import importlib

    import f5waf.api as api
    importlib.reload(api)
    from fastapi.testclient import TestClient
    c = TestClient(api.app)
    H = {"X-API-Key": "k1"}
    assert c.get("/api/checks").status_code == 401
    r = c.post("/api/scans", json={}, headers=H)
    assert r.status_code == 202
    sid = r.json()["scan_id"]
    assert c.get(f"/api/scans/{sid}", headers=H).json()["status"] == "completed"
    f = c.get("/api/scans/latest/findings", params={"min_severity": "HIGH"}, headers=H).json()
    assert f["count"] > 0 and all(x["severity"] in ("CRITICAL", "HIGH") for x in f["findings"])
    assert c.get("/api/partitions/P_ACME", headers=H).status_code == 200
    for fmt in ("html", "xlsx", "json", "csv"):
        assert c.get(f"/api/scans/{sid}/report.{fmt}", headers=H).status_code == 200
    assert c.post("/api/scans", json={"devices": ["yok"]}, headers=H).status_code == 400
