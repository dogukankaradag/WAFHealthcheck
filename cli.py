"""Komut satırı arayüzü.

Örnekler:
  python cli.py scan -c config.yaml
  python cli.py scan -c config.yaml --device waf01 --partition "P_ACME*" --fail-on HIGH
  python cli.py checks
  python cli.py check-access -c config.yaml              # config/.env'den okunan bilgileri göster
  python cli.py check-access -c config.yaml --ask        # beklenen parolayla karşılaştır (ekrana yazmaz)
  python cli.py check-access -c config.yaml --login      # her cihaza TEK giriş denemesi
  python cli.py serve -c config.yaml --port 8080
"""
from __future__ import annotations

import argparse
import logging
import os
import re
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


def cmd_user(a):
    import getpass
    from f5waf.auth import ROLES, hash_password, password_problem
    from f5waf.state import StateStore
    store = StateStore(Config.load(a.config).state_db)
    if a.action == "list":
        for u in store.list_users():
            print(f"{u['id']:>3}  {u['username']:<20} {u['role']:<9} {'aktif' if u['is_active'] else 'pasif'}  {u['full_name'] or ''}")
        return
    if not a.username:
        sys.exit("Kullanıcı adı gerekli: python cli.py user add <ad>")
    pw = a.password or getpass.getpass("Parola: ")
    if (p := password_problem(pw)):
        sys.exit(p)
    u = store.get_user(a.username)
    if a.action == "add":
        if u:
            sys.exit("Bu kullanıcı zaten var; parolayı değiştirmek için 'passwd' kullanın.")
        if a.role not in ROLES:
            sys.exit("Rol admin veya readonly olmalı.")
        store.create_user(a.username, hash_password(pw), a.role, a.full_name or "")
        print(f"Kullanıcı oluşturuldu: {a.username} ({a.role})")
    else:  # passwd
        if not u:
            sys.exit("Kullanıcı bulunamadı.")
        store.update_user(u["id"], password_hash=hash_password(pw), is_active=1)
        print(f"Parola güncellendi: {a.username}")


def _env_file_problems(path: str) -> list[str]:
    probs = []
    raw = open(path, "rb").read()
    if raw.startswith(b"\xef\xbb\xbf"):
        probs.append("dosya UTF-8 BOM ile başlıyor (Windows Notepad) - systemd ilk satırı yanlış okuyabilir")
    if b"\r\n" in raw:
        probs.append("Windows satır sonu (CRLF) var - düzeltmek için: sed -i 's/\\r$//' .env")
    seen = {}
    for no, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        t = line.strip()
        if not t or t.startswith("#") or "=" not in t:
            continue
        key, val = t.split("=", 1)
        if key != key.rstrip() or val != val.lstrip():
            probs.append(f"{no}. satır: '=' işaretinin etrafında boşluk var ({key.strip()})")
        k = key.strip().removeprefix("export ").strip()
        if k in seen:
            probs.append(f"{no}. satır: {k} ikinci kez tanımlanmış ({seen[k]}. satırda da var)")
        seen[k] = no
        v = val.strip()
        if k.endswith(("PASS", "PASSWORD")) and v[:1] not in ("'", '"') and any(ch in v for ch in "$#\\ `\"'"):
            probs.append(f"{no}. satır: {k} değeri özel karakter içeriyor ama tırnaksız - tek tırnağa alın: {k}='...'")
    return probs


def _pw_flags(pw: str) -> list[str]:
    f = []
    if not pw:
        return f
    if pw != pw.strip():
        f.append("başında/sonunda boşluk")
    if "\r" in pw:
        f.append("\\r karakteri (CRLF)")
    if pw[:1] in "'\"" or pw[-1:] in "'\"":
        f.append("tırnak işareti parolanın parçası olmuş")
    if re.search(r"\$\{?[A-Za-z_]", pw):
        f.append("içinde $ var - systemd/shell bunu değişken sanıp kesmiş olabilir; --ask ile karşılaştırın")
    if any(ord(ch) > 127 for ch in pw):
        f.append("Türkçe/ASCII dışı karakter")
    return f


def cmd_check_access(a):
    import getpass
    import hashlib
    from f5waf.client import F5Error
    from f5waf.scanner import make_client
    cfg_path = os.path.abspath(a.config)
    env_path = os.path.join(os.path.dirname(cfg_path), ".env")
    before = {k for k in os.environ}
    cfg = Config.load(cfg_path)
    print(f"Config : {cfg_path}")
    if os.path.isfile(env_path):
        print(f".env   : {env_path}")
        for p in _env_file_problems(env_path):
            print(f"  [UYARI] .env {p}")
    else:
        print(f".env   : YOK ({env_path})")
    refs = sorted(set(re.findall(r"\$\{([A-Za-z0-9_]+)\}", open(cfg_path, encoding="utf-8").read())))
    for name in refs:
        src = ("TANIMSIZ -> boş değer" if name in cfg.missing_env else
               "ortamdan (shell/systemd) - .env'deki değer KULLANILMADI" if name in before else ".env")
        print(f"  ${{{name}}} <- {src}")
    if cfg.missing_env:
        print("  [UYARI] Tanımsız değişken var; ilgili alanlar boş gidecek.")
    devices = [d for d in cfg.devices if not a.device or d.get("name") in a.device]
    expected = {}
    print()
    for d in devices:
        pw = str(d.get("password") or "")
        user = str(d.get("username") or "")
        print(f"[{d.get('name')}] host={d.get('host')}  provider={d.get('login_provider', 'tmos')}  "
              f"verify_ssl={d.get('verify_ssl', True)}{'  (MOCK)' if d.get('mock') else ''}")
        print(f"    kullanıcı : {user!r}" + ("  <- BOŞ" if not user else "")
              + ("  <- boşluk var" if user != user.strip() else ""))
        fp = hashlib.sha256(pw.encode()).hexdigest()[:8] if pw else "-"
        print(f"    parola    : {len(pw)} karakter, parmak izi {fp}" + ("  <- BOŞ" if not pw else ""))
        for f in _pw_flags(pw):
            print(f"    [UYARI] parola: {f}")
        if a.ask and pw:
            if user not in expected:
                expected[user] = getpass.getpass(f"    '{user}' için cihazda tanımlı parolayı yazın (görünmez): ")
            ok = expected[user] == pw
            print(f"    karşılaştırma: {'EŞLEŞİYOR' if ok else 'EŞLEŞMİYOR - uygulama farklı bir parola okuyor'}"
                  + ("" if ok else f" (beklenen {len(expected[user])} karakter)"))
        if a.login and not d.get("mock"):
            try:
                c = make_client(d)
                ver = c.get("/mgmt/tm/sys/version")
                desc = ""
                for ent in (ver.get("entries") or {}).values():
                    desc = ent.get("nestedStats", {}).get("entries", {}).get("Version", {}).get("description", "")
                print(f"    giriş     : BAŞARILI (TMOS {desc})")
                try:
                    n = len(c.get_items("/mgmt/tm/auth/partition"))
                    print(f"    partition : {n} adet görülebiliyor")
                except F5Error as e:
                    print(f"    partition : okunamadı - {e}")
                c.logout()
            except Exception as e:  # noqa: BLE001
                print(f"    giriş     : BAŞARISIZ - {e}")
        print()
    if not a.login:
        print("Cihaza bağlanılmadı. Tek giriş denemesi için --login ekleyin.")


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
    u = sub.add_parser("user", help="Web arayüzü kullanıcıları: list | add | passwd")
    u.add_argument("action", choices=["list", "add", "passwd"])
    u.add_argument("username", nargs="?")
    u.add_argument("-c", "--config", default="config.yaml")
    u.add_argument("--role", default="readonly", help="add için: admin | readonly")
    u.add_argument("--full-name")
    u.add_argument("--password", help="Verilmezse sorulur (önerilen)")
    u.set_defaults(fn=cmd_user)
    k = sub.add_parser("check-access", help="Cihaz bilgilerini ve (isteğe bağlı) girişi kontrol et")
    k.add_argument("-c", "--config", default="config.yaml")
    k.add_argument("--device", action="append", help="Yalnızca bu cihaz(lar)")
    k.add_argument("--ask", action="store_true", help="Beklenen parolayı sor ve okunan değerle karşılaştır")
    k.add_argument("--login", action="store_true", help="Her cihaza tek giriş denemesi yap")
    k.set_defaults(fn=cmd_check_access)
    v = sub.add_parser("serve", help="Web arayüzü + API'yi başlat")
    v.add_argument("-c", "--config", default="config.yaml")
    v.add_argument("--host", default="0.0.0.0")
    v.add_argument("--port", type=int, default=4467)
    v.set_defaults(fn=cmd_serve)
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    a.fn(a)


if __name__ == "__main__":
    main()
