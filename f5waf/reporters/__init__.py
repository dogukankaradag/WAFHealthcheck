"""Rapor üreticileri: HTML, Excel, JSON, CSV.

Hepsi `report` sözlüğünü alır (ScanResult.to_report() veya API'nin DB'den kurduğu yapı).
"""
from __future__ import annotations

import csv
import json
import os

from ..models import SEVERITIES

CSV_FIELDS = ["severity", "status", "check_id", "title", "category", "device", "partition", "customer",
              "object_type", "object_name", "detail", "recommendation", "first_seen", "suppressed",
              "suppress_reason", "fingerprint"]


def write_json(report: dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)
    return path


def write_csv(report: dict, path: str) -> str:
    with open(path, "w", encoding="utf-8-sig", newline="") as f:  # BOM: Excel Türkçe karakter uyumu
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore", delimiter=";")
        w.writeheader()
        for row in report["findings"]:
            w.writerow(row)
    return path


def write_all(report: dict, out_dir: str, formats: list[str]) -> dict[str, str]:
    from .html import write_html
    from .xlsx import write_xlsx
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"waf-healthcheck-{report['scan_id']}")
    writers = {"json": write_json, "csv": write_csv, "html": write_html, "xlsx": write_xlsx}
    return {fmt: writers[fmt](report, f"{base}.{fmt}") for fmt in formats if fmt in writers}


__all__ = ["write_all", "write_json", "write_csv", "SEVERITIES"]
