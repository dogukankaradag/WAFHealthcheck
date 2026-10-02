"""SQLite tabanlı durum takibi.

- scans:        her taramanın özeti
- findings:     taramalardaki bulgular (JSON)
- observations: bir durumun (ör. policy transparent) ilk/son görülme zamanı
"""
from __future__ import annotations

import json
import os
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
"""


class StateStore:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._seen_this_scan: set[str] = set()

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
        import re
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
    def start_scan(self, scan_id: str, started_at: datetime) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO scans (id, started_at, status) VALUES (?,?,?)",
                               (scan_id, started_at.isoformat(), "running"))
            self._conn.commit()

    def finish_scan(self, scan_id: str, *, status: str, summary: dict, devices: list[dict],
                    findings: list[dict], error: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET finished_at=?, status=?, summary=?, devices=?, error=? WHERE id=?",
                (datetime.now(timezone.utc).isoformat(), status, json.dumps(summary),
                 json.dumps(devices), error, scan_id))
            self._conn.executemany(
                "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [(scan_id, f["fingerprint"], f["check_id"], f["severity"], f["device"], f["partition"],
                  f["customer"], f["object_name"], f["status"], int(f["suppressed"]),
                  json.dumps(f, ensure_ascii=False, default=str)) for f in findings])
            self._conn.commit()

    def previous_scan_id(self, before: str) -> str | None:
        row = self._conn.execute(
            "SELECT id FROM scans WHERE status IN ('completed','partial') AND id < ? ORDER BY id DESC LIMIT 1",
            (before,)).fetchone()
        return row["id"] if row else None

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
        rows = self._conn.execute("SELECT data FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._scan_row(r) for r in rows]

    def get_scan(self, scan_id: str) -> dict | None:
        r = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return self._scan_row(r) if r else None

    @staticmethod
    def _scan_row(r) -> dict:
        d = dict(r)
        for k in ("summary", "devices"):
            d[k] = json.loads(d[k]) if d.get(k) else None
        return d
