"""Web arayüzü kimlik doğrulama.

fwcheck ile aynı mantık: kullanıcı adı/parola ile giriş, imzalı oturum token'ı (8 saat),
roller admin (tarama başlatma, durum değiştirme, kullanıcı yönetimi) ve readonly (görüntüleme, rapor).
Ek bağımlılık olmaması için PBKDF2 + HMAC-SHA256 (standart kütüphane) kullanılır.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from .state import StateStore

ROLES = ("admin", "readonly")
TOKEN_HOURS = int(os.environ.get("F5WAF_TOKEN_HOURS", "8"))
_ITER = 200_000


# ------------------------------------------------------------------ parola
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITER)
    return f"pbkdf2_sha256${_ITER}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, it, salt, h = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk.hex(), h)
    except (ValueError, TypeError):
        return False


def password_problem(password: str) -> str | None:
    if len(password or "") < 8:
        return "Parola en az 8 karakter olmalı."
    return None


# ------------------------------------------------------------------- token
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class TokenSigner:
    def __init__(self, store: StateStore):
        key = os.environ.get("F5WAF_SECRET_KEY") or store.get_meta("secret_key")
        if not key:
            key = secrets.token_hex(32)
            store.set_meta("secret_key", key)  # yeniden başlatmada oturumlar düşmesin
        self.key = key.encode()

    def issue(self, username: str, role: str) -> str:
        payload = _b64(json.dumps({"sub": username, "role": role,
                                   "exp": int(time.time()) + TOKEN_HOURS * 3600}).encode())
        sig = _b64(hmac.new(self.key, payload.encode(), hashlib.sha256).digest())
        return f"{payload}.{sig}"

    def verify(self, token: str) -> dict | None:
        try:
            payload, sig = token.split(".")
            good = _b64(hmac.new(self.key, payload.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(sig, good):
                return None
            data = json.loads(_unb64(payload))
            return data if data.get("exp", 0) > time.time() else None
        except (ValueError, json.JSONDecodeError):
            return None


# ------------------------------------------------------- deneme sınırlama
class LoginThrottle:
    """Aynı kullanıcı adı için 5 hatalı denemeden sonra 5 dakika kilit."""

    def __init__(self, max_fail: int = 5, window: int = 300):
        self.max_fail, self.window = max_fail, window
        self.fails: dict[str, list[float]] = {}

    def blocked(self, username: str) -> int:
        now = time.time()
        f = [t for t in self.fails.get(username, []) if now - t < self.window]
        self.fails[username] = f
        return int(self.window - (now - f[0])) if len(f) >= self.max_fail else 0

    def fail(self, username: str) -> None:
        self.fails.setdefault(username, []).append(time.time())

    def reset(self, username: str) -> None:
        self.fails.pop(username, None)


def ensure_default_admin(store: StateStore, log) -> None:
    """İlk çalıştırmada admin kullanıcısını oluşturur.
    Parola F5WAF_ADMIN_PASSWORD ortam değişkeninden alınır; yoksa rastgele üretilip loga yazılır."""
    if store.count_users() > 0:
        return
    pw = os.environ.get("F5WAF_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    store.create_user("admin", hash_password(pw), "admin", "Sistem Yöneticisi")
    if os.environ.get("F5WAF_ADMIN_PASSWORD"):
        log.warning("Varsayılan kullanıcı oluşturuldu: admin (parola F5WAF_ADMIN_PASSWORD değişkeninden)")
    else:
        log.warning("=" * 60)
        log.warning("  Varsayılan kullanıcı oluşturuldu")
        log.warning("  Kullanıcı: admin   Parola: %s", pw)
        log.warning("  İlk girişten sonra Kullanıcılar ekranından parolayı değiştirin.")
        log.warning("=" * 60)
