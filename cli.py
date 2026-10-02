"""Komut satırı arayüzü.

Örnekler:
  python cli.py scan -c config.yaml
  python cli.py scan -c config.yaml --device waf01 --partition "P_ACME*" --fail-on HIGH
  python cli.py checks
  python cli.py serve -c config.yaml --port 8080
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from f5waf.checks import catalog
from f5waf.models import SEVERITIES, Config
from f5waf.reporters import write_all
from f5waf.scanner import Scanner


def cmd_scan(a):
    cfg = Config.load(a.config)
    if a.formats:
        cfg.formats = a.formats.split(",")
    res = Scanner(cfg).run(devices=a.device or None, partitions=a.partition or None)
    rep = res.to_report()
    files = write_all(rep, a.output or cfg.output_dir, cfg.formats)
    s = rep["summary"]
    print(f"\nTarama {res.scan_id} [{res.status}]  cihaz {s['devices_ok']}/{s['devices_total']}  "
          f"partition {len(s['partitions'])}")
    for d in res.devices:
        print(f"  {'OK ' if d.ok else 'ERR'} {d.name:<12} {d.version:<10} {d.stats}  {d.error}")
    print("  " + "  ".join(f"{k}:{v}" for k, v in s["by_severity"].items())
          + f"  | yeni:{s['new']} kapanan:{s['resolved']} istisna:{s['suppressed']}")
    print("\nEn riskli partition'lar:")
    for p in s["partitions"][:10]:
        if p["score"]:
            print(f"  {p['score']:>4}  {p['device']:<10} {p['partition']:<20} C{p['CRITICAL']} H{p['HIGH']} M{p['MEDIUM']}")
    print("\nRaporlar:")
    for fmt, path in files.items():
        print(f"  {fmt:<5} {os.path.abspath(path)}")
    if a.fail_on:  # CI / izleme entegrasyonu için çıkış kodu
        limit = SEVERITIES.index(a.fail_on)
        if any(SEVERITIES.index(f.severity) <= limit for f in res.active):
            sys.exit(2)
    if res.status == "failed":
        sys.exit(1)


def cmd_checks(_):
    for c in catalog():
        print(f"{c['id']:<9} [{c['category']}] {c['title']}\n          {c['description']}\n")


def cmd_serve(a):
    import uvicorn
    os.environ["F5WAF_CONFIG"] = a.config
    uvicorn.run("f5waf.api:app", host=a.host, port=a.port)


def main():
    ap = argparse.ArgumentParser(prog="f5-waf-healthcheck")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Tarama yap ve rapor üret")
    s.add_argument("-c", "--config", default="config.yaml")
    s.add_argument("--device", action="append", help="Yalnızca bu cihaz(lar) (tekrarlanabilir)")
    s.add_argument("--partition", action="append", help="Partition filtresi, joker destekli (tekrarlanabilir)")
    s.add_argument("--formats", help="html,xlsx,json,csv")
    s.add_argument("-o", "--output", help="Rapor klasörü")
    s.add_argument("--fail-on", choices=SEVERITIES, help="Bu seviye veya üstü bulgu varsa çıkış kodu 2")
    s.set_defaults(fn=cmd_scan)
    c = sub.add_parser("checks", help="Kontrol kataloğunu listele")
    c.set_defaults(fn=cmd_checks)
    v = sub.add_parser("serve", help="REST API'yi başlat")
    v.add_argument("-c", "--config", default="config.yaml")
    v.add_argument("--host", default="0.0.0.0")
    v.add_argument("--port", type=int, default=8080)
    v.set_defaults(fn=cmd_serve)
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    a.fn(a)


if __name__ == "__main__":
    main()
