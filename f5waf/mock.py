"""Test/demo için sahte BIG-IP istemcisi.

Gerçek iControl REST yanıt yapısını taklit eder; config'de `mock: true` olan cihazlar bunu kullanır.
Üç sanal WAF cihazı ve onlarca müşteri partition'ı deterministik olarak üretilir.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc)

CUSTOMERS = ["ACME", "BETA_BANK", "CITY_MUN", "DELTA_LOG", "EKO_MARKET", "FINTEK", "GAMA_SIG", "HIZLI_KARGO",
             "ILKE_EDU", "JET_TUR", "KALE_INS", "LIMAN_AS", "MERKEZ_HAST", "NOVA_TEL", "OPTIMA", "PARK_OTO",
             "RADYO_X", "SAFIR_ENERJI", "TREND_MODA", "UZAY_YAZ", "VEGA_FIN", "YILDIZ_GIDA", "ZIRVE_INS"]

SIG_SETS = ["Generic Detection Signatures (High/Medium Accuracy)", "SQL Injection Signatures",
            "Cross Site Scripting Signatures", "Command Execution Signatures", "Server Side Code Injection Signatures"]
VIOLS = ["Attack signature detected", "Evasion technique detected", "HTTP protocol compliance failed",
         "Illegal method", "Illegal file type", "Malformed JSON data", "Threat Campaign detected",
         "Illegal meta character in value", "Illegal URL", "Illegal parameter", "Modified ASM cookie"]


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _stats(kind: str, items: dict[str, dict]) -> dict:
    return {"entries": {f"https://localhost/mgmt/tm/ltm/{kind}/{fp.replace('/', '~')}/stats": {
        "nestedStats": {"entries": {"tmName": {"description": fp},
                                    **{k: {"description": v} for k, v in st.items()}}}}
        for fp, st in items.items()}}


class MockClient:
    def __init__(self, name: str, profile: str):
        self.name, self.host = name, f"mock://{name}"
        rnd = random.Random(profile)
        idx = {"waf01": 0, "waf02": 1, "waf03": 2}.get(profile, rnd.randint(0, 2))
        custs = CUSTOMERS[idx::3]
        self.partitions = ["Common"] + [f"P_{c}" for c in custs]
        self.virtuals, self.vstats, self.pools, self.pstats, self.policies = [], {}, [], {}, []
        self.policy_detail: dict[str, dict] = {}
        self.certs, self.clientssl = [], []
        for c in custs:
            part = f"P_{c}"
            for n in range(rnd.randint(1, 3)):
                app = f"{c.lower()}_web{n + 1}"
                vs, pool = f"/{part}/vs_{app}_443", f"/{part}/pool_{app}"
                members = [{"name": f"10.{idx}.{rnd.randint(1, 250)}.{i}:443",
                            "state": "up", "session": "monitor-enabled"} for i in range(rnd.randint(1, 4))]
                roll = rnd.random()
                if roll < 0.08:
                    for m in members:
                        m["state"] = "down"
                elif roll < 0.16 and len(members) > 2:
                    for m in members[1:]:
                        m["state"] = "down"
                pool_obj = {"name": f"pool_{app}", "partition": part, "fullPath": pool,
                            "monitor": "" if rnd.random() < 0.07 else "/Common/https",
                            "membersReference": {"items": members}}
                self.pools.append(pool_obj)
                self.pstats[pool] = {"status.availabilityState": "offline" if all(m["state"] == "down" for m in members) else "available"}
                has_waf = rnd.random() > 0.12
                vs_obj = {"name": f"vs_{app}_443", "partition": part, "fullPath": vs, "pool": pool,
                          "destination": f"/{part}/185.{idx}.{rnd.randint(1, 250)}.{n + 10}:443",
                          "profilesReference": {"items": [
                              {"fullPath": "/Common/http"}, {"fullPath": f"/{part}/clientssl_{app}"}]},
                          "securityLogProfiles": [] if rnd.random() < 0.15 else ['"/Common/Log illegal requests"']}
                self.virtuals.append(vs_obj)
                # her uygulama için HTTPS'e yönlendiren 80 portlu VS (WAF'sız, pool'suz)
                self.virtuals.append({"name": f"vs_{app}_80", "partition": part, "fullPath": f"/{part}/vs_{app}_80",
                                      "destination": vs_obj["destination"].rsplit(":", 1)[0] + ":80",
                                      "rules": ["/Common/_sys_https_redirect"],
                                      "profilesReference": {"items": [{"fullPath": "/Common/http"}]}})
                self.vstats[f"/{part}/vs_{app}_80"] = {"status.availabilityState": "unknown",
                                                       "status.enabledState": "enabled"}
                if rnd.random() < 0.1:  # SSL passthrough (L4) VS - WAF'ı atlar
                    self.virtuals.append({"name": f"vs_{app}_8443_l4", "partition": part,
                                          "fullPath": f"/{part}/vs_{app}_8443_l4", "pool": pool,
                                          "destination": vs_obj["destination"].rsplit(":", 1)[0] + ":8443",
                                          "profilesReference": {"items": [{"fullPath": "/Common/fastL4"}]}})
                    self.vstats[f"/{part}/vs_{app}_8443_l4"] = {"status.availabilityState": "available",
                                                                "status.enabledState": "enabled"}
                avail = "offline" if all(m["state"] == "down" for m in members) else (
                    "unknown" if not pool_obj["monitor"] else "available")
                self.vstats[vs] = {"status.availabilityState": avail,
                                   "status.enabledState": "disabled" if rnd.random() < 0.04 else "enabled",
                                   "status.statusReason": "The children pool member(s) are down" if avail == "offline" else ""}
                cert = f"/{part}/{app}.crt"
                exp = NOW + timedelta(days=rnd.choice([-12, 9, 25, 45, 180, 300, 400, 500]))
                self.certs.append({"name": f"{app}.crt", "partition": part, "fullPath": cert,
                                   "expirationDate": int(exp.timestamp()), "subject": f"CN={app}.example.com.tr"})
                self.clientssl.append({"fullPath": f"/{part}/clientssl_{app}", "cert": cert})
                if has_waf:
                    self._make_policy(rnd, part, app, [vs])
            if rnd.random() < 0.3:  # sahipsiz policy
                self._make_policy(rnd, part, f"{c.lower()}_old", [])
        # partition dışı (Common) bir VS - HTTP değil
        self.virtuals.append({"name": "vs_dns", "partition": "Common", "fullPath": "/Common/vs_dns",
                              "pool": "", "rules": ["/Common/dns_rule"], "profilesReference": {"items": [{"fullPath": "/Common/udp"}]}})
        self.vstats["/Common/vs_dns"] = {"status.availabilityState": "available", "status.enabledState": "enabled"}
        self.asu_days = [8, 75, 140][idx]
        self.sync = ["In Sync", "Changes Pending", "In Sync"][idx]
        self.version = ["16.1.4", "17.1.1", "15.1.10"][idx]
        self.broken_policy = rnd.choice(self.policies)["id"] if self.policies else None

    def _make_policy(self, rnd, part, app, vss):
        pid = f"{rnd.getrandbits(48):012x}"
        transparent = rnd.random() < 0.35
        created = NOW - timedelta(days=rnd.randint(20, 900))
        changed = NOW - timedelta(days=rnd.randint(1, 120 if transparent else 60))
        self.policies.append({
            "id": pid, "name": f"asm_{app}", "partition": part, "fullPath": f"/{part}/asm_{app}",
            "enforcementMode": "transparent" if transparent else "blocking", "active": rnd.random() > 0.05,
            "virtualServers": vss, "createdDatetime": _iso(created), "versionDatetime": _iso(max(changed, created)),
            "isModified": rnd.random() < 0.1})
        self.policy_detail[pid] = {
            "general": {"enforcementReadinessPeriod": 7, "trustXff": rnd.random() < 0.15, "customXffHeaders": []},
            "policy-builder": {"learningMode": rnd.choice(["manual", "manual", "automatic", "disabled"])},
            "signature-settings": {"signatureStaging": True, "placeSignaturesInStaging": True},
            "signature-sets": [{"signatureSetReference": {"name": s, "link": "https://localhost/x"},
                                "alarm": True, "block": rnd.random() > 0.07, "learn": True} for s in SIG_SETS],
            "violations": [{"description": v, "alarm": rnd.random() > 0.03, "block": rnd.random() > 0.12, "learn": True}
                           for v in VIOLS],
            "staged": rnd.choice([0, 0, 0, 3, 12, 48, 260]),
            "disabled": rnd.choice([0, 2, 5, 14, 75, 180]),
        }

    # ------------------------------------------------------------------ API
    def logout(self):
        pass

    def get(self, path, params=None, *, allow_404=False):
        if path == "/mgmt/tm/sys/version":
            return {"entries": {"x": {"nestedStats": {"entries": {"Version": {"description": self.version}}}}}}
        if path.startswith("/mgmt/tm/asm/policies/"):
            pid, sub = path.split("/")[5], "/".join(path.split("/")[6:])
            if pid == self.broken_policy and sub == "blocking-settings/violations":
                from .client import F5Error
                raise F5Error("GET violations -> 503 ASM REST busy")
            d = self.policy_detail[pid]
            if sub in ("general", "policy-builder", "signature-settings"):
                return d[sub]
            if sub == "signature-sets":
                return {"items": d["signature-sets"]}
            if sub == "blocking-settings/violations":
                return {"items": d["violations"]}
            if sub == "signatures":
                flt = (params or {}).get("$filter", "")
                n = d["staged"] if "performStaging" in flt else d["disabled"]
                return {"items": [{"id": "x"}] if n else [], "totalItems": n}
        return {"items": self.get_items(path, params)}

    def get_items(self, path, params=None, *, allow_404=False):
        if path.startswith("/mgmt/tm/asm/policies/"):
            return self.get(path, params).get("items", [])
        m = {
            "/mgmt/tm/auth/partition": [{"name": p} for p in self.partitions],
            "/mgmt/tm/ltm/virtual": self.virtuals,
            "/mgmt/tm/ltm/pool": self.pools,
            "/mgmt/tm/ltm/profile/http": [{"fullPath": "/Common/http"}],
            "/mgmt/tm/ltm/profile/client-ssl": self.clientssl,
            "/mgmt/tm/sys/file/ssl-cert": self.certs,
            "/mgmt/tm/asm/policies": self.policies,
            "/mgmt/tm/live-update/asm-attack-signatures/installations": [
                {"filename": f"ASM-AttackSignatures_{(NOW - timedelta(days=self.asu_days)):%Y%m%d_%H%M%S}.im",
                 "status": "install-complete"}],
        }
        return list(m.get(path, []))

    def count(self, path, flt):
        return self.get(path, {"$filter": flt}).get("totalItems", 0)

    def get_stats(self, path):
        if path == "/mgmt/tm/ltm/virtual/stats":
            src = self.vstats
        elif path == "/mgmt/tm/ltm/pool/stats":
            src = self.pstats
        elif path == "/mgmt/tm/cm/sync-status":
            return {"/Common/sync": {"status": self.sync}}
        elif path == "/mgmt/tm/cm/failover-status":
            return {"/Common/fo": {"status": "ACTIVE"}}
        else:
            return {}
        return {fp: {"tmName": fp, **st} for fp, st in src.items()}
