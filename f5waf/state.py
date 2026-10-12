"""SQLite tabanlı durum deposu.

- scans:           her taramanın özeti (kim başlattı, durum, cihaz sonuçları)
- findings:        taramalardaki bulgular (JSON)
- observations:    bir durumun (ör. policy transparent) ilk/son görülme zamanı
- finding_status:  bulgu iş akışı (Açık / Onaylandı / İşlemde / Çözüldü), taramalar arası kalıcı
- users:           web arayüzü kullanıcıları (admin / readonly)
- meta:            anahtar-değer (ör. oturum imzalama anahtarı)

Tek bağlantı birden fazla thread'den (API + arka plan taraması) kullanıldığı için
tüm erişimler kilit altındadır.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT, status TEXT,
    summary TEXT, devices TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id TEXT, fingerprint TEXT, check_id TEXT, severity TEXT, device TEXT,
    partition TEXT, customer TEXT, object_name TEXT, status TEXT, suppressed INTEGER, data TEXT,
    PRIMARY KEY (scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS ix_findings_fp ON findings(fingerprint);
CREATE TABLE IF NOT EXISTS observations (
    key TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS finding_status (
    fingerprint TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'open', comment TEXT,
    assigned_to TEXT, updated_by TEXT, updated_at TEXT,
    snapshot TEXT, is_changed INTEGER DEFAULT 0, changed_at TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, full_name TEXT,
    password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'readonly',
    is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

MIGRATIONS = [("scans", "triggered_by", "TEXT DEFAULT 'cli'"),
              ("scans", "request", "TEXT")]

WORKFLOW_STATUSES = ("open", "acknowledged", "in_progress", "resolved")

# Kanıtta günden güne kendiliğinden değişen alanlar; "çözüldükten sonra değişti" kontrolünde yok sayılır
VOLATILE_EVIDENCE = {"days_transparent", "observed_days", "policy_age_days", "days_left", "days",
                     "last_change", "expires"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def finding_snapshot(f: dict) -> str:
    ev = {k: v for k, v in (f.get("evidence") or {}).items() if k not in VOLATILE_EVIDENCE}
    return json.dumps({"object": f.get("object_name"), "evidence": ev}, sort_keys=True, default=str)


class StateStore:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            for table, col, ddl in MIGRATIONS:
                cols = {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}
                if col not in cols:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
            self._conn.commit()
        self._seen_this_scan: set[str] = set()

    # ------------------------------------------------------------------ meta
    def get_meta(self, key: str) -> str | None:
        with self._lock:
            r = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return r["value"] if r else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, value))
            self._conn.commit()

    # --------------------------------------------------------- observations
    def observe(self, key: str, now: datetime | None = None) -> datetime:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            self._seen_this_scan.add(key)
            row = self._conn.execute("SELECT first_seen FROM observations WHERE key=?", (key,)).fetchone()
            if row:
                self._conn.execute("UPDATE observations SET last_seen=? WHERE key=?", (now.isoformat(), key))
                return datetime.fromisoformat(row["first_seen"])
            self._conn.execute("INSERT INTO observations VALUES (?,?,?)", (key, now.isoformat(), now.isoformat()))
            return now

    def prune_observations(self, scope: dict[str, set[str]]) -> None:
        """Bu taramada görülmeyen durumları sil (durum düzeldiyse sayaç sıfırlansın).
        Yalnızca bu taramada gerçekten taranan cihaz/partition'lara dokunur."""
        with self._lock:
            for dev, parts in scope.items():
                rows = self._conn.execute("SELECT key FROM observations WHERE key LIKE ?", (f"{dev}|%",)).fetchall()
                for r in rows:
                    m = re.search(r"\|/([^/]+)/", r["key"])
                    if m and m.group(1) not in parts:
                        continue
                    if r["key"] not in self._seen_this_scan:
                        self._conn.execute("DELETE FROM observations WHERE key=?", (r["key"],))
            self._conn.commit()
            self._seen_this_scan.clear()

    # --------------------------------------------------------------- scans
    def start_scan(self, scan_id: str, started_at: datetime, triggered_by: str = "cli",
                   request: dict | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO scans (id, started_at, status, triggered_by, request) VALUES (?,?,?,?,?)",
                (scan_id, started_at.isoformat(), "running", triggered_by, json.dumps(request or {})))
            self._conn.commit()

    def finish_scan(self, scan_id: str, *, status: str, summary: dict, devices: list[dict],
                    findings: list[dict], error: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET finished_at=?, status=?, summary=?, devices=?, error=? WHERE id=?",
                (_now(), status, json.dumps(summary, default=str), json.dumps(devices, default=str), error, scan_id))
            self._conn.executemany(
                "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [(scan_id, f["fingerprint"], f["check_id"], f["severity"], f["device"], f["partition"],
                  f["customer"], f["object_name"], f["status"], int(f["suppressed"]),
                  json.dumps(f, ensure_ascii=False, default=str)) for f in findings])
            self._conn.commit()

    def fail_scan(self, scan_id: str, error: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE scans SET finished_at=?, status='failed', error=? WHERE id=?",
                               (_now(), error, scan_id))
            self._conn.commit()

    def mark_interrupted(self) -> int:
        """Sunucu yeniden başlarken 'running' kalmış taramaları kapat."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE scans SET status='failed', finished_at=?, error='Tarama yarıda kaldı (sunucu yeniden başlatıldı)' "
                "WHERE status='running'", (_now(),))
            self._conn.commit()
            return cur.rowcount

    def running_scan(self) -> dict | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM scans WHERE status='running' ORDER BY started_at DESC LIMIT 1").fetchone()
            return self._scan_row(r) if r else None

    def previous_scan_id(self, before: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM scans WHERE status IN ('completed','partial') AND id < ? ORDER BY id DESC LIMIT 1",
                (before,)).fetchone()
            return row["id"] if row else None

    def previous_findings(self, scan_id: str, scope: dict[str, set[str]], limit: int = 200) -> list[dict]:
        """Bu taramanın kapsamındaki her (cihaz, partition) için, onu kapsayan EN SON önceki taramanın bulguları."""
        with self._lock:
            cur = self._conn.execute("SELECT started_at FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not cur:
                return []
            rows = self._conn.execute(
                "SELECT id, devices FROM scans WHERE status IN ('completed','partial') AND id != ? "
                "AND started_at <= ? ORDER BY started_at DESC LIMIT ?", (scan_id, cur["started_at"], limit)).fetchall()
        wanted = {(d, p) for d, ps in scope.items() for p in ps}
        covered: set[tuple[str, str]] = set()
        out: list[dict] = []
        for r in rows:
            new: set[tuple[str, str]] = set()
            for d in json.loads(r["devices"] or "[]"):
                if d.get("ok"):
                    new |= {(d["name"], p) for p in (d.get("partitions") or [])} | {(d["name"], "(cihaz)")}
            new = (new & wanted) - covered
            if new:
                out += [f for f in self.findings_of(r["id"]) if (f["device"], f["partition"]) in new]
                covered |= new
            if covered == wanted:
                break
        return out

    def latest_scan(self) -> dict | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM scans WHERE status IN ('completed','partial') "
                                   "ORDER BY started_at DESC LIMIT 1").fetchone()
            return self._scan_row(r) if r else None

    def first_seen_map(self, fingerprints: list[str]) -> dict[str, str]:
        """Her bulgunun ilk görüldüğü tarama zamanı."""
        out: dict[str, str] = {}
        with self._lock:
            for fp in fingerprints:
                row = self._conn.execute(
                    "SELECT s.started_at FROM findings f JOIN scans s ON s.id=f.scan_id "
                    "WHERE f.fingerprint=? ORDER BY s.started_at ASC LIMIT 1", (fp,)).fetchone()
                if row:
                    out[fp] = row["started_at"]
        return out

    def findings_of(self, scan_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT data FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._scan_row(r) for r in rows]

    def get_scan(self, scan_id: str) -> dict | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return self._scan_row(r) if r else None

    @staticmethod
    def _scan_row(r) -> dict:
        d = dict(r)
        for k in ("summary", "devices", "request"):
            d[k] = json.loads(d[k]) if d.get(k) else None
        return d

    # ------------------------------------------------------ finding status
    def status_map(self) -> dict[str, dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM finding_status").fetchall()
        return {r["fingerprint"]: dict(r) for r in rows}

    def set_status(self, fingerprint: str, status: str, *, comment: str | None, assigned_to: str | None,
                   user: str, finding: dict | None) -> dict:
        if status not in WORKFLOW_STATUSES:
            raise ValueError(status)
        snap = finding_snapshot(finding) if (status == "resolved" and finding) else None
        with self._lock:
            self._conn.execute(
                "INSERT INTO finding_status (fingerprint,status,comment,assigned_to,updated_by,updated_at,"
                "snapshot,is_changed,changed_at) VALUES (?,?,?,?,?,?,?,0,NULL) "
                "ON CONFLICT(fingerprint) DO UPDATE SET status=excluded.status, comment=excluded.comment, "
                "assigned_to=excluded.assigned_to, updated_by=excluded.updated_by, updated_at=excluded.updated_at, "
                "snapshot=excluded.snapshot, is_changed=0, changed_at=NULL",
                (fingerprint, status, comment, assigned_to, user, _now(), snap))
            self._conn.commit()
            return dict(self._conn.execute("SELECT * FROM finding_status WHERE fingerprint=?",
                                           (fingerprint,)).fetchone())

    def detect_changes(self, findings: list[dict]) -> int:
        """'Çözüldü' işaretlenmiş bulgunun nesnesi/kanıtı sonradan değiştiyse işaretle."""
        changed = 0
        with self._lock:
            rows = {r["fingerprint"]: r for r in self._conn.execute(
                "SELECT fingerprint, snapshot, is_changed FROM finding_status WHERE status='resolved'")}
            for f in findings:
                r = rows.get(f["fingerprint"])
                if r and r["snapshot"] and not r["is_changed"] and finding_snapshot(f) != r["snapshot"]:
                    self._conn.execute("UPDATE finding_status SET is_changed=1, changed_at=? WHERE fingerprint=?",
                                       (_now(), f["fingerprint"]))
                    changed += 1
            self._conn.commit()
        return changed

    # --------------------------------------------------------------- users
    def count_users(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def list_users(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        return [{k: r[k] for k in r.keys() if k != "password_hash"} for r in rows]

    def get_user(self, username: str | None = None, user_id: int | None = None) -> dict | None:
        with self._lock:
            if user_id is not None:
                r = self._conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            else:
                r = self._conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None

    def create_user(self, username: str, password_hash: str, role: str, full_name: str = "") -> dict:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO users (username, full_name, password_hash, role, is_active, created_at) "
                "VALUES (?,?,?,?,1,?)", (username, full_name, password_hash, role, _now()))
            self._conn.commit()
            return self.get_user(user_id=cur.lastrowid)

    def update_user(self, user_id: int, **fields) -> dict | None:
        allowed = {k: v for k, v in fields.items()
                   if k in ("full_name", "password_hash", "role", "is_active") and v is not None}
        if allowed:
            with self._lock:
                sets = ", ".join(f"{k}=?" for k in allowed)
                self._conn.execute(f"UPDATE users SET {sets} WHERE id=?", (*allowed.values(), user_id))
                self._conn.commit()
        return self.get_user(user_id=user_id)

    def delete_user(self, user_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            self._conn.commit()
