"""F5 BIG-IP iControl REST istemcisi (salt okunur).

- Token tabanlı kimlik doğrulama (/mgmt/shared/authn/login)
- Token süresini uzatma ve 401'de otomatik yeniden login
- nextLink / $top-$skip sayfalama
- Tüm çağrılar GET; cihazda hiçbir değişiklik yapılmaz
  (token süresi uzatma PATCH'i hariç - o da yalnızca kendi token'ımız üzerinde).
"""
from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from typing import Any, Iterator
from urllib.parse import urlparse

import requests
import urllib3

log = logging.getLogger(__name__)


class F5Error(Exception):
    pass


# Reddedilen giriş bilgileri (süreç ömrü boyunca). Aynı host+kullanıcı+parola ile tekrar tekrar
# denenip cihazdaki hesabın kilitlenmesini (max-login-failures) önlemek için kullanılır.
_AUTH_FAILURES: dict[str, tuple[float, str]] = {}
_AUTH_LOCK = threading.Lock()
AUTH_RETRY_AFTER = 30 * 60  # sn - aynı bilgilerle tekrar denemeden önce beklenecek süre


def _auth_key(host: str, username: str, password: str) -> str:
    return hashlib.sha256(f"{host}\0{username}\0{password}".encode()).hexdigest()


def clear_auth_failures() -> None:
    with _AUTH_LOCK:
        _AUTH_FAILURES.clear()


class F5Client:
    TOKEN_LIFETIME = 3600  # sn

    def __init__(self, host: str, username: str, password: str, *,
                 login_provider: str = "tmos", verify_ssl: bool | str = True,
                 timeout: int = 60, page_size: int = 500, retries: int = 3):
        self.host = host.rstrip("/")
        if not self.host.startswith("http"):
            self.host = f"https://{self.host}"
        self.username = username
        self.password = password
        self.login_provider = login_provider
        self.timeout = timeout
        self.page_size = page_size
        self.retries = retries
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if verify_ssl is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._token: str | None = None
        self._token_expiry = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ auth
    def login(self) -> None:
        with self._lock:
            if self._token and time.time() < self._token_expiry - 60:
                return
            if not self.username or not self.password:
                raise F5Error(f"{self.host}: kullanıcı adı/parola boş - config.yaml'daki "
                              "${F5_USER}/${F5_PASS} değişkenleri .env'de tanımlı mı? "
                              "(veya username/password değerlerini doğrudan yazın)")
            key = _auth_key(self.host, self.username, self.password)
            with _AUTH_LOCK:
                prev = _AUTH_FAILURES.get(key)
            if prev and time.time() - prev[0] < AUTH_RETRY_AFTER:
                left = int((AUTH_RETRY_AFTER - (time.time() - prev[0])) / 60) + 1
                raise F5Error(
                    f"{self.host}: bu kullanıcı adı/parola ile giriş daha önce reddedildi ({prev[1]}). "
                    f"Hesabın kilitlenmemesi için tekrar denenmedi. Bilgileri/kilidi düzeltip servisi "
                    f"yeniden başlatın ya da ~{left} dk sonra tekrar deneyin.")
            r = self.session.post(
                f"{self.host}/mgmt/shared/authn/login",
                json={"username": self.username, "password": self.password,
                      "loginProviderName": self.login_provider},
                timeout=self.timeout)
            if r.status_code != 200:
                msg = r.text[:200]
                try:
                    msg = r.json().get("message") or msg
                except ValueError:
                    pass
                if r.status_code in (401, 403):
                    with _AUTH_LOCK:
                        _AUTH_FAILURES[key] = (time.time(), msg)
                    if "maximum number of login attempts" in msg.lower():
                        msg += (" -> Hesap cihazda kilitlenmiş. System > Users > User List'te kullanıcıyı "
                                "seçip Unlock edin (tmsh: reset-stats auth login-failures <kullanıcı>).")
                raise F5Error(f"{self.host}: login başarısız ({r.status_code}) {msg}")
            token = r.json()["token"]["token"]
            self.session.headers["X-F5-Auth-Token"] = token
            self._token = token
            self._token_expiry = time.time() + 1200  # varsayılan ömür
            try:  # ömrü uzat (uzun taramalar için)
                p = self.session.patch(f"{self.host}/mgmt/shared/authz/tokens/{token}",
                                       json={"timeout": self.TOKEN_LIFETIME}, timeout=self.timeout)
                if p.status_code == 200:
                    self._token_expiry = time.time() + self.TOKEN_LIFETIME
            except requests.RequestException:
                pass
            log.info("%s: token alındı", self.host)

    def logout(self) -> None:
        if self._token:
            try:
                self.session.delete(f"{self.host}/mgmt/shared/authz/tokens/{self._token}",
                                    timeout=self.timeout)
            except requests.RequestException:
                pass
            self._token = None

    # ------------------------------------------------------------------ http
    def _url(self, path: str) -> str:
        if path.startswith("http"):
            # nextLink'ler "https://localhost/..." döner, gerçek host ile değiştir
            u = urlparse(path)
            return f"{self.host}{u.path}" + (f"?{u.query}" if u.query else "")
        return f"{self.host}{path}"

    def get(self, path: str, params: dict | None = None, *, allow_404: bool = False) -> dict:
        self.login()
        url = self._url(path)
        last_exc: Exception | None = None
        for attempt in range(1, self.retries + 1):
            try:
                r = self.session.get(url, params=params, timeout=self.timeout)
            except requests.RequestException as e:
                last_exc = e
                time.sleep(attempt * 2)
                continue
            if r.status_code == 401:
                self._token = None
                self.login()
                continue
            if r.status_code == 404 and allow_404:
                return {}
            if r.status_code in (500, 502, 503, 504):
                last_exc = F5Error(f"{r.status_code} {r.text[:200]}")
                time.sleep(attempt * 2)
                continue
            if r.status_code != 200:
                raise F5Error(f"GET {path} -> {r.status_code} {r.text[:300]}")
            return r.json()
        raise F5Error(f"GET {path} başarısız: {last_exc}")

    def get_items(self, path: str, params: dict | None = None, *, allow_404: bool = False) -> list[dict]:
        """Koleksiyonu tüm sayfalarıyla döndürür."""
        return list(self.iter_items(path, params, allow_404=allow_404))

    def iter_items(self, path: str, params: dict | None = None, *, allow_404: bool = False) -> Iterator[dict]:
        params = dict(params or {})
        data = self.get(path, params, allow_404=allow_404)
        yield from data.get("items", [])
        seen = 0
        while data.get("nextLink") and seen < 10000:
            seen += 1
            data = self.get(data["nextLink"])
            yield from data.get("items", [])

    def count(self, path: str, flt: str) -> int:
        """ASM koleksiyonlarında filtreye uyan kayıt sayısı (totalItems)."""
        data = self.get(path, {"$filter": flt, "$top": 1, "$select": "id"}, allow_404=True)
        if "totalItems" in data:
            return int(data["totalItems"])
        return len(data.get("items", []))

    def get_stats(self, path: str) -> dict[str, dict[str, Any]]:
        """/stats çıktısını {fullPath: {stat: değer}} sözlüğüne düzleştirir."""
        data = self.get(path, allow_404=True)
        out: dict[str, dict[str, Any]] = {}
        for url, ent in (data.get("entries") or {}).items():
            nested = ent.get("nestedStats", {}).get("entries", {})
            flat = {k: (v.get("description") if "description" in v else v.get("value"))
                    for k, v in nested.items()}
            name = flat.get("tmName")
            if not name:
                m = re.search(r"/(~[^/]+)/stats$", url)
                name = m.group(1).replace("~", "/") if m else url
            out[name] = flat
        return out
