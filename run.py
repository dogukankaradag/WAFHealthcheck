"""WAF Healthcheck web arayüzünü başlatır (fwcheck'teki run.py ile aynı kullanım).

    python run.py                       # config.yaml varsa onu, yoksa demo config'i kullanır
    python run.py config.demo.yaml      # belirli bir config ile
    python run.py --port 4500           # farklı port

Ortam değişkenleri: F5WAF_PORT (varsayılan 4467), F5WAF_HOST (varsayılan 0.0.0.0),
F5WAF_ADMIN_PASSWORD (ilk admin parolası), F5_USER / F5_PASS (cihaz kimlik bilgileri).
"""
import logging
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)                 # state/, reports/ ve config yolları her zaman proje klasörüne göre
sys.path.insert(0, HERE)


def fail(msg: str) -> None:
    print(f"\n[HATA] {msg}\n")
    sys.exit(1)


def main() -> None:
    args = sys.argv[1:]
    port = int(os.environ.get("F5WAF_PORT", "4467"))
    if "--port" in args:
        i = args.index("--port")
        port = int(args[i + 1])
        del args[i:i + 2]
    host = os.environ.get("F5WAF_HOST", "0.0.0.0")

    if sys.version_info < (3, 10):
        fail(f"Python 3.10 veya üzeri gerekli (şu an {sys.version.split()[0]}).")
    missing = []
    for mod, pkg in [("fastapi", "fastapi"), ("uvicorn", "uvicorn"), ("yaml", "PyYAML"),
                     ("openpyxl", "openpyxl"), ("requests", "requests"), ("multipart", "python-multipart")]:
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        fail("Eksik paket(ler): " + ", ".join(missing) +
             "\n        Önce sanal ortamı etkinleştirip kurun:\n"
             "        .\\.venv\\Scripts\\Activate.ps1\n        pip install -r requirements.txt")

    config = args[0] if args else os.environ.get("F5WAF_CONFIG") or (
        "config.yaml" if os.path.exists("config.yaml") else "config.demo.yaml")
    if not os.path.exists(config):
        fail(f"Config dosyası bulunamadı: {os.path.join(HERE, config)}")
    os.environ["F5WAF_CONFIG"] = config

    from f5waf.models import Config
    try:
        cfg = Config.load(config)
    except Exception as e:  # YAML hatası vb.
        fail(f"Config okunamadı ({config}): {e}")
    warnings = []
    if cfg.missing_env:
        warnings.append("Tanımsız ortam değişkeni: " + ", ".join(cfg.missing_env) +
                        "  (.env dosyasında tanımlayın)")
    for d in cfg.devices:
        if not d.get("mock") and (not d.get("username") or not d.get("password")):
            warnings.append(f"{d.get('name')}: kullanıcı adı/parola boş - tarama 401 ile başarısız olur")

    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", port)) == 0:
            fail(f"{port} portu başka bir uygulama tarafından kullanılıyor.\n"
                 f"        Farklı port için: python run.py --port {port + 1}")

    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    print("=" * 60)
    print("  WAF Healthcheck")
    print(f"  Config : {config}{'  (DEMO - sahte cihazlar)' if 'demo' in config else ''}")
    print(f"  Adres  : http://localhost:{port}")
    print(f"  API    : http://localhost:{port}/api/docs")
    print("  Durdurmak için Ctrl+C")
    for w in warnings:
        print(f"  [UYARI] {w}")
    print("=" * 60)

    import uvicorn
    uvicorn.run("f5waf.api:app", host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
