"""Healthcheck kuralları.

Her kural bir `Check` kaydıdır: kimlik, başlık, kategori ve bulgu üreten fonksiyon.
Yeni kural eklemek için `@check(...)` dekoratörüyle bir fonksiyon yazmak yeterli.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable

from .collector import DeviceSnapshot, PolicyData, parse_ts, partition_of
from .models import Config, Finding

DEVICE_PARTITION = "(cihaz)"


class Context:
    """Kurallara verilen çalışma bağlamı."""

    def __init__(self, snap: DeviceSnapshot, cfg: Config, observe: Callable[[str], datetime]):
        self.snap = snap
        self.cfg = cfg
        self.now = snap.collected_at
        self._observe = observe
        # VS -> policy eşlemesi
        self.vs_policy: dict[str, PolicyData] = {}
        for p in snap.policies:
            for vs in p.raw.get("virtualServers") or []:
                self.vs_policy[vs] = p
        self.pool_users: dict[str, list[str]] = {}
        for v in snap.virtuals:
            if v.get("pool"):
                self.pool_users.setdefault(v["pool"], []).append(v["fullPath"])

    def observe(self, key: str) -> datetime:
        """Durumun ilk görüldüğü zamanı döndürür (state DB)."""
        return self._observe(f"{self.snap.name}|{key}")

    def t(self, name: str, partition: str):
        return self.cfg.threshold(name, partition)

    def finding(self, chk: "Check", severity: str, partition: str, object_type: str,
                object_name: str, detail: str, recommendation: str | None = None, **evidence) -> Finding:
        return Finding(
            check_id=chk.id, title=chk.title, severity=severity, category=chk.category,
            device=self.snap.name, partition=partition, object_type=object_type,
            object_name=object_name, detail=detail,
            recommendation=recommendation or chk.recommendation, evidence=evidence,
            customer=self.cfg.customer_of(partition))


@dataclass
class Check:
    id: str
    title: str
    category: str
    description: str
    recommendation: str
    fn: Callable[["Check", Context], Iterable[Finding]]


REGISTRY: list[Check] = []


def check(id: str, title: str, category: str, description: str, recommendation: str):
    def deco(fn):
        REGISTRY.append(Check(id, title, category, description, recommendation, fn))
        return fn
    return deco


def _days(delta) -> int:
    return max(0, int(delta.total_seconds() // 86400))


def _pol_partition(p: PolicyData) -> str:
    return p.raw.get("partition") or partition_of(p.full_path)


def _set_name(s: dict) -> str:
    ref = s.get("signatureSetReference") or {}
    return ref.get("name") or s.get("name") or ref.get("link", "?").rsplit("/", 1)[-1].split("?")[0]


# =====================================================================  WAF POLICY
@check("WAF-001", "WAF policy transparent modda", "WAF Policy",
       "Transparent moddaki policy saldırıları yalnızca loglar, engellemez. Süre; cihazdaki son "
       "değişiklik zamanı ve önceki taramalarda ilk görülme zamanından hesaplanır (alt sınır).",
       "Staging/learning önerilerini gözden geçirip policy'yi Blocking moda alın. "
       "Geçiş planı varsa suppressions ile bitiş tarihli istisna tanımlayın.")
def chk_transparent(chk, ctx):
    for p in ctx.snap.policies:
        if str(p.raw.get("enforcementMode", "")).lower() != "transparent":
            continue
        part = _pol_partition(p)
        first_obs = ctx.observe(f"transparent|{p.full_path}")
        last_change = parse_ts(p.raw.get("versionDatetime") or p.raw.get("lastUpdateMicros")
                               or p.raw.get("createdDatetime"))
        days = _days(ctx.now - first_obs)
        if last_change:
            days = max(days, _days(ctx.now - last_change))
        vs = p.raw.get("virtualServers") or []
        if not vs:
            continue  # VS'e bağlı olmayan policy'ler WAF-003'te raporlanır
        if days >= ctx.t("transparent_critical_days", part):
            sev = "CRITICAL"
        elif days >= ctx.t("transparent_max_days", part):
            sev = "HIGH"
        else:
            sev = "MEDIUM"
        yield ctx.finding(chk, sev, part, "asm-policy", p.full_path,
                          f"Policy en az {days} gündür transparent modda; {len(vs)} VS korumasız "
                          f"(yalnızca izleme).",
                          days_transparent=days, virtual_servers=vs,
                          last_change=last_change.isoformat() if last_change else None,
                          threshold_days=ctx.t("transparent_max_days", part))


@check("WAF-002", "WAF policy pasif (inactive) ancak VS'e atanmış", "WAF Policy",
       "Pasif policy trafiği denetlemez; VS WAF korumasız çalışıyor olabilir.",
       "Policy'yi 'Apply' edip aktif hale getirin veya VS üzerindeki bağlantıyı düzeltin.")
def chk_inactive(chk, ctx):
    for p in ctx.snap.policies:
        if p.raw.get("active", True) is False and p.raw.get("virtualServers"):
            yield ctx.finding(chk, "HIGH", _pol_partition(p), "asm-policy", p.full_path,
                              "Policy inactive durumda fakat VS'lere atanmış görünüyor.",
                              virtual_servers=p.raw.get("virtualServers"))


@check("WAF-003", "Hiçbir VS'e bağlı olmayan (sahipsiz) WAF policy", "WAF Policy",
       "Kullanılmayan policy'ler konfigürasyon kirliliği yaratır; müşterinin korunduğu varsayımına yol açabilir.",
       "Müşteri servisinin gerçekten WAF arkasında olup olmadığını doğrulayın; gereksizse policy'yi kaldırın.")
def chk_orphan(chk, ctx):
    for p in ctx.snap.policies:
        if not p.raw.get("virtualServers"):
            yield ctx.finding(chk, "LOW", _pol_partition(p), "asm-policy", p.full_path,
                              f"Policy herhangi bir VS'e bağlı değil (mod: {p.raw.get('enforcementMode')}).")


@check("WAF-004", "Enforce edilmesi gereken imzalar staging'de bekliyor", "Signature",
       "Staging'deki imzalar blocking modda bile engelleme yapmaz. Enforcement readiness süresi "
       "dolduktan sonra da staging'de kalan imzalar koruma açığıdır.",
       "Traffic Learning > 'Enforce Ready' imzaları inceleyip enforce edin; "
       "false-positive olanları istisna olarak tanımlayın.")
def chk_staging(chk, ctx):
    for p in ctx.snap.policies:
        n = p.staged_signatures
        if n is None:
            continue
        part = _pol_partition(p)
        if n < ctx.t("staging_min_signatures", part) or not p.raw.get("virtualServers"):
            continue
        readiness = int(p.general.get("enforcementReadinessPeriod")
                        or p.policy_builder.get("enforcementReadinessPeriod") or 7)
        first_obs = ctx.observe(f"staging|{p.full_path}")
        created = parse_ts(p.raw.get("createdDatetime"))
        age = _days(ctx.now - first_obs)
        policy_age = _days(ctx.now - created) if created else 0
        limit = readiness + ctx.t("staging_max_days", part)
        if max(age, policy_age) < limit:
            continue
        blocking = str(p.raw.get("enforcementMode", "")).lower() == "blocking"
        sev = "HIGH" if blocking else "MEDIUM"
        yield ctx.finding(chk, sev, part, "asm-policy", p.full_path,
                          f"{n} imza staging'de; readiness süresi {readiness} gün, staging durumu en az "
                          f"{age} gündür gözlemleniyor (policy yaşı {policy_age} gün).",
                          staged_signatures=n, readiness_days=readiness,
                          observed_days=age, policy_age_days=policy_age)


@check("WAF-005", "Signature set engelleme (block) kapalı", "Signature",
       "Block bayrağı kapalı olan signature set'ler policy blocking modda olsa da yalnızca alarm üretir.",
       "Signature set için Block seçeneğini açın.")
def chk_sigset_block(chk, ctx):
    for p in ctx.snap.policies:
        if not p.raw.get("virtualServers"):
            continue
        part = _pol_partition(p)
        for s in p.signature_sets:
            if s.get("block") is False:
                sev = "HIGH" if s.get("alarm", True) else "CRITICAL"
                yield ctx.finding(chk, sev, part, "signature-set", f"{p.full_path} :: {_set_name(s)}",
                                  f"Signature set '{_set_name(s)}' block=False, alarm={s.get('alarm')}.",
                                  policy=p.full_path, alarm=s.get("alarm"), learn=s.get("learn"))


@check("WAF-006", "Kritik ihlal (violation) engellenmiyor", "Blocking Settings",
       "Saldırı imzası, evasion, HTTP uyumsuzluğu gibi kritik ihlallerde block bayrağı kapalı.",
       "Learning and Blocking Settings altında ilgili ihlal için Block'u açın.")
def chk_violations(chk, ctx):
    critical = {v.lower() for v in ctx.cfg.critical_violations}
    for p in ctx.snap.policies:
        if not p.raw.get("virtualServers"):
            continue
        part = _pol_partition(p)
        bad_block, bad_alarm = [], []
        for v in p.violations:
            desc = v.get("description") or v.get("name") or ""
            if desc.lower() not in critical:
                continue
            if v.get("alarm") is False and v.get("block") is False:
                bad_alarm.append(desc)
            elif v.get("block") is False:
                bad_block.append(desc)
        if bad_alarm:
            yield ctx.finding(chk, "HIGH", part, "asm-policy", f"{p.full_path} :: görünmez ihlaller",
                              f"Alarm ve block kapalı (tespit bile loglanmıyor): {', '.join(bad_alarm)}",
                              policy=p.full_path, violations=bad_alarm)
        if bad_block:
            core = {"attack signature detected", "evasion technique detected", "threat campaign detected"}
            sev = "HIGH" if core & {b.lower() for b in bad_block} else "MEDIUM"
            yield ctx.finding(chk, sev, part, "asm-policy", f"{p.full_path} :: engellenmeyen ihlaller",
                              f"Yalnızca alarm (block kapalı): {', '.join(bad_block)}",
                              policy=p.full_path, violations=bad_block)


@check("WAF-007", "Çok sayıda devre dışı imza", "Signature",
       "Devre dışı bırakılan imzalar kalıcı kör noktalardır; genelde false-positive nedeniyle toptan kapatılır.",
       "Devre dışı imzaları gözden geçirin; mümkünse imzayı kapatmak yerine parametre/URL bazlı istisna kullanın.")
def chk_disabled_sigs(chk, ctx):
    for p in ctx.snap.policies:
        n = p.disabled_signatures
        part = _pol_partition(p)
        if n is not None and n > ctx.t("disabled_signatures_max", part) and p.raw.get("virtualServers"):
            yield ctx.finding(chk, "MEDIUM", part, "asm-policy", p.full_path,
                              f"{n} imza devre dışı (eşik {ctx.t('disabled_signatures_max', part)}).",
                              disabled_signatures=n)


@check("WAF-008", "Policy Builder / learning yapılandırması riskli", "WAF Policy",
       "Transparent modda learning kapalıysa policy hiç olgunlaşmaz; blocking modda otomatik learning "
       "incelemesiz gevşemeye yol açabilir.",
       "Transparent policy'lerde learning'i açın; blocking policy'lerde otomatik learning'i manuel'e çekin.")
def chk_learning(chk, ctx):
    for p in ctx.snap.policies:
        if not p.raw.get("virtualServers") or not p.policy_builder:
            continue
        mode = str(p.policy_builder.get("learningMode", "")).lower()
        enf = str(p.raw.get("enforcementMode", "")).lower()
        part = _pol_partition(p)
        if enf == "transparent" and mode == "disabled":
            yield ctx.finding(chk, "MEDIUM", part, "asm-policy", p.full_path,
                              "Policy transparent modda fakat learning kapalı; blocking'e geçiş için veri toplanmıyor.",
                              learning_mode=mode, enforcement=enf)
        elif enf == "blocking" and mode == "automatic":
            yield ctx.finding(chk, "LOW", part, "asm-policy", p.full_path,
                              "Blocking modda otomatik learning açık; policy incelemesiz gevşeyebilir.",
                              learning_mode=mode, enforcement=enf)


@check("WAF-009", "Trust XFF açık", "WAF Policy",
       "X-Forwarded-For'a güvenmek, önünde güvenilir proxy yoksa istemci IP'sinin sahtelenmesine "
       "(IP istisnaları / IP intelligence atlatma) izin verir.",
       "Önünde CDN/proxy yoksa Trust XFF'i kapatın; varsa kaynak IP kısıtlamasını doğrulayın.")
def chk_xff(chk, ctx):
    for p in ctx.snap.policies:
        if p.general.get("trustXff") and p.raw.get("virtualServers"):
            yield ctx.finding(chk, "LOW", _pol_partition(p), "asm-policy", p.full_path,
                              "Trust XFF etkin." + (" Özel başlıklar: " + ", ".join(p.general.get("customXffHeaders") or [])
                                                    if p.general.get("customXffHeaders") else ""))


@check("WAF-010", "Uygulanmamış (Apply edilmemiş) policy değişiklikleri", "WAF Policy",
       "Policy üzerinde yapılan değişiklikler Apply edilmediği için trafiğe yansımıyor.",
       "Değişiklikleri inceleyip Apply Policy yapın veya geri alın.")
def chk_unapplied(chk, ctx):
    for p in ctx.snap.policies:
        if p.raw.get("isModified") is True:
            yield ctx.finding(chk, "MEDIUM", _pol_partition(p), "asm-policy", p.full_path,
                              "Policy'de apply edilmemiş değişiklik var.")


@check("WAF-011", "Policy denetlenemedi", "Görünürlük",
       "Policy alt kaynaklarından biri okunamadığı için ilgili kontroller yapılamadı; "
       "durum bilinmiyor demektir.",
       "Tarama kullanıcısının ilgili partition'da en az Auditor/Guest yetkisi olduğunu ve ASM REST'in "
       "yanıt verdiğini doğrulayın.")
def chk_policy_errors(chk, ctx):
    for p in ctx.snap.policies:
        if p.errors:
            yield ctx.finding(chk, "MEDIUM", _pol_partition(p), "asm-policy", p.full_path,
                              "Okunamayan alanlar: " + "; ".join(e.split(":")[0] for e in p.errors),
                              errors=p.errors)


# =====================================================================  LTM
@check("LTM-001", "Virtual server erişilemez / devre dışı", "Erişilebilirlik",
       "VS offline veya unknown durumda; servis kesintisi ya da izlenemeyen servis.",
       "Pool/monitor durumunu ve statusReason'ı kontrol edin.")
def chk_vs_status(chk, ctx):
    for v in ctx.snap.virtuals:
        fp = v["fullPath"]
        st = ctx.snap.virtual_stats.get(fp, {})
        avail = str(st.get("status.availabilityState", "")).lower()
        enabled = str(st.get("status.enabledState", "enabled")).lower()
        reason = st.get("status.statusReason", "")
        part = v.get("partition") or partition_of(fp)
        if enabled == "disabled":
            yield ctx.finding(chk, "INFO", part, "virtual", fp, f"VS yönetici tarafından devre dışı. {reason}",
                              recommendation="Kullanılmıyorsa kaldırın; kullanılıyorsa etkinleştirin.")
        elif avail == "offline":
            yield ctx.finding(chk, "HIGH", part, "virtual", fp, f"VS offline. {reason}",
                              destination=v.get("destination"), pool=v.get("pool"))
        elif avail == "unknown" and v.get("pool"):  # pool'suz (redirect) VS'ler her zaman unknown görünür
            yield ctx.finding(chk, "LOW", part, "virtual", fp,
                              f"VS durumu unknown (monitor yok ya da kontrol edilemiyor). {reason}",
                              recommendation="Pool'a health monitor atayarak durum takibini mümkün kılın.")


@check("LTM-002", "Pool sağlık sorunu", "Erişilebilirlik",
       "Pool üyelerinin tamamı/çoğu down, pool boş ya da monitor tanımlı değil.",
       "Backend sunucuların ve monitor'ün durumunu kontrol edin; monitor'süz pool'lara monitor atayın.")
def chk_pools(chk, ctx):
    for p in ctx.snap.pools:
        fp = p["fullPath"]
        part = p.get("partition") or partition_of(fp)
        members = (p.get("membersReference") or {}).get("items", [])
        users = ctx.pool_users.get(fp, [])
        if not members:
            if users:
                yield ctx.finding(chk, "HIGH", part, "pool", fp, "Pool'da hiç üye yok fakat VS tarafından kullanılıyor.",
                                  used_by=users)
            continue
        down = [m["name"] for m in members if str(m.get("state", "")).lower() in ("down", "user-down")
                or str(m.get("session", "")).lower() == "user-disabled"]
        if not p.get("monitor") and all(str(m.get("monitor", "default")).lower() in ("default", "", "none")
                                        for m in members):
            yield ctx.finding(chk, "LOW", part, "pool", fp,
                              "Pool'a health monitor atanmamış; üye durumu takip edilemiyor.", used_by=users)
        if len(down) == len(members):
            yield ctx.finding(chk, "HIGH" if users else "MEDIUM", part, "pool", fp,
                              f"Tüm üyeler down ({len(down)}/{len(members)}).", down_members=down, used_by=users)
        elif len(down) / len(members) > ctx.t("pool_partial_down_ratio", part):
            yield ctx.finding(chk, "MEDIUM", part, "pool", fp,
                              f"Üyelerin çoğunluğu down ({len(down)}/{len(members)}); yedeklilik kaybı.",
                              down_members=down, used_by=users)


def _profiles(v: dict) -> list[str]:
    return [x.get("fullPath") or f"/{x.get('partition')}/{x.get('name')}"
            for x in (v.get("profilesReference") or {}).get("items", [])]


def vs_port(destination: str | None) -> int | None:
    """'/P/10.0.0.1:443', '/P/10.0.0.1%12:443' veya IPv6 '/P/2001:db8::1.443' -> 443. 'any' -> 0."""
    if not destination:
        return None
    addr = destination.rsplit("/", 1)[-1]
    sep = "." if addr.count(":") > 1 else ":"   # IPv6'da port ayırıcı nokta
    port = addr.rsplit(sep, 1)[-1]
    if port == "any":
        return 0
    return int(port) if port.isdigit() else None


@check("LTM-003", "WAF policy'si olmayan virtual server", "Kapsam",
       "VS'e bağlı bir WAF policy'si yok; trafik denetlenmiyor. 'no_waf_exempt_ports' listesindeki "
       "portlar (varsayılan 80 — yalnızca HTTPS'e yönlendirme yapan VS'ler) raporlanmaz. HTTP profili "
       "olmayan (L4 / SSL passthrough) VS'ler WAF'ı tamamen atlar ve ayrıca listelenir.",
       "VS'e müşterinin WAF policy'sini atayın; L4 VS'ler için HTTP profili + WAF'lı yapıya geçişi "
       "değerlendirin ya da WAF hizmeti dışında olduğunu istisna olarak kaydedin.")
def chk_vs_no_waf(chk, ctx):
    waf_parts = {_pol_partition(p) for p in ctx.snap.policies}
    exempt = {int(p) for p in ctx.cfg.no_waf_exempt_ports}
    for v in ctx.snap.virtuals:
        fp = v["fullPath"]
        part = v.get("partition") or partition_of(fp)
        if fp in ctx.vs_policy:
            continue
        if ctx.cfg.only_waf_partitions and part not in waf_parts:
            continue
        if any(v.get(k) for k in ("ipForward", "l2Forward", "reject", "internal")):
            continue
        port = vs_port(v.get("destination"))
        if port in exempt:
            continue
        is_http = any(pr in ctx.snap.http_profiles or pr.endswith("/http") for pr in _profiles(v))
        if is_http:
            yield ctx.finding(chk, "HIGH", part, "virtual", fp,
                              f"HTTP VS (port {port}) üzerinde WAF policy yok.",
                              destination=v.get("destination"), port=port, http_profile=True)
        elif ctx.cfg.no_waf_include_non_http:
            yield ctx.finding(chk, "MEDIUM", part, "virtual", fp,
                              f"VS (port {port}) HTTP profili içermiyor; WAF uygulanamaz, trafik L4 olarak geçiyor.",
                              destination=v.get("destination"), port=port, http_profile=False)


@check("LTM-004", "WAF'lı VS'de güvenlik log profili yok", "Görünürlük",
       "Security logging profili olmadan WAF olayları kaydedilmez; saldırı takibi ve SIEM beslemesi yapılamaz.",
       "VS'e uygun Security Log Profile (ör. Log illegal requests + remote logging) atayın.")
def chk_vs_logging(chk, ctx):
    for v in ctx.snap.virtuals:
        fp = v["fullPath"]
        if fp in ctx.vs_policy and not v.get("securityLogProfiles"):
            yield ctx.finding(chk, "MEDIUM", v.get("partition") or partition_of(fp), "virtual", fp,
                              f"WAF policy {ctx.vs_policy[fp].full_path} bağlı, security log profili yok.")


@check("LTM-005", "Varsayılan pool'u olmayan VS", "Erişilebilirlik",
       "VS'in default pool'u ve iRule'u yok; trafik iletilemiyor olabilir.",
       "Yapılandırmayı doğrulayın veya kullanılmayan VS'i kaldırın.")
def chk_vs_nopool(chk, ctx):
    for v in ctx.snap.virtuals:
        forwarding = any(v.get(k) for k in ("ipForward", "l2Forward", "reject", "internal"))
        if not v.get("pool") and not v.get("rules") and not forwarding \
                and not (v.get("policiesReference") or {}).get("items"):
            fp = v["fullPath"]
            yield ctx.finding(chk, "LOW", v.get("partition") or partition_of(fp), "virtual", fp,
                              "VS'in default pool'u, iRule'u veya LTM policy'si yok.")


# =====================================================================  CERT
@check("CERT-001", "SSL sertifikası süresi dolmuş / dolmak üzere", "Sertifika",
       "Client-SSL profillerinde kullanılan sertifikaların son kullanma tarihi.",
       "Sertifikayı yenileyip ilgili client-ssl profilini güncelleyin.")
def chk_certs(chk, ctx):
    used: dict[str, list[str]] = {}
    for prof in ctx.snap.clientssl_profiles:
        certs = [prof.get("cert")] + [k.get("cert") for k in prof.get("certKeyChain") or []]
        for c in filter(None, certs):
            used.setdefault(c, []).append(prof.get("fullPath"))
    for c in ctx.snap.certs:
        fp = c.get("fullPath") or f"/{c.get('partition')}/{c.get('name')}"
        if fp.startswith("/Common/") and fp not in used:
            continue  # Common'daki kullanılmayan sistem/CA sertifikalarını atla
        exp = parse_ts(c.get("expirationDate"))
        if not exp:
            continue
        days = int((exp - ctx.now).total_seconds() // 86400)
        part = c.get("partition") or partition_of(fp)
        if days < 0:
            sev, msg = "CRITICAL", f"Sertifikanın süresi {-days} gün önce dolmuş."
        elif days <= ctx.t("cert_expiry_high_days", part):
            sev, msg = "HIGH", f"Sertifikanın süresi {days} gün içinde doluyor."
        elif days <= ctx.t("cert_expiry_warn_days", part):
            sev, msg = "MEDIUM", f"Sertifikanın süresi {days} gün içinde doluyor."
        else:
            continue
        if fp not in used:
            sev = {"CRITICAL": "LOW", "HIGH": "LOW", "MEDIUM": "INFO"}[sev]
            msg += " (Hiçbir client-ssl profilinde kullanılmıyor.)"
        yield ctx.finding(chk, sev, part, "ssl-cert", fp, msg, expires=exp.date().isoformat(),
                          days_left=days, subject=c.get("subject") or c.get("commonName"),
                          used_by=used.get(fp, []))


# =====================================================================  DEVICE
@check("DEV-001", "Attack signature veritabanı güncel değil", "Cihaz",
       "Yüklü ASU (Attack Signature Update) paketinin yaşı eşiği aşıyor; yeni saldırı imzaları eksik.",
       "Live Update üzerinden güncel attack signature paketini kurun; otomatik güncellemeyi planlayın.")
def chk_asu(chk, ctx):
    limit = ctx.cfg.thresholds["signature_update_max_days"]
    if ctx.snap.signature_update is None:
        yield ctx.finding(chk, "LOW", DEVICE_PARTITION, "device", ctx.snap.name,
                          "Yüklü attack signature paketinin tarihi okunamadı.")
        return
    days = _days(ctx.now - ctx.snap.signature_update)
    if days > limit:
        yield ctx.finding(chk, "HIGH" if days > limit * 3 else "MEDIUM", DEVICE_PARTITION, "device",
                          ctx.snap.name, f"Son signature paketi {days} gün önce ({ctx.snap.signature_update_name}).",
                          days=days, package=ctx.snap.signature_update_name)


@check("DEV-002", "HA cihazlar senkron değil", "Cihaz",
       "Config sync durumu 'In Sync' değil; failover durumunda farklı WAF kuralları devreye girebilir.",
       "Device group sync durumunu inceleyip senkronizasyonu tamamlayın.")
def chk_sync(chk, ctx):
    s = ctx.snap.sync_status
    if s and s.lower() not in ("in sync", "standalone"):
        yield ctx.finding(chk, "MEDIUM", DEVICE_PARTITION, "device", ctx.snap.name,
                          f"Sync durumu: {s} (failover: {ctx.snap.failover_status or '?'}).")


@check("DEV-003", "Cihaz verisi eksik toplandı", "Görünürlük",
       "Bazı koleksiyonlar okunamadı; bu cihazdaki sonuçlar eksik olabilir.",
       "Hata mesajlarını ve kullanıcı yetkilerini kontrol edin.")
def chk_device_warnings(chk, ctx):
    for w in ctx.snap.warnings:
        yield ctx.finding(chk, "MEDIUM", DEVICE_PARTITION, "device", f"{ctx.snap.name} :: {w.split(':')[0]}", w)


def run_checks(snap: DeviceSnapshot, cfg: Config, observe) -> list[Finding]:
    ctx = Context(snap, cfg, observe)
    out: list[Finding] = []
    for chk in REGISTRY:
        if chk.id in cfg.disabled_checks:
            continue
        try:
            out.extend(chk.fn(chk, ctx))
        except Exception as e:  # tek kural hatası tüm taramayı düşürmesin
            out.append(ctx.finding(chk, "INFO", DEVICE_PARTITION, "check", chk.id,
                                   f"Kural çalıştırılırken hata: {e!r}"))
    return out


def catalog() -> list[dict]:
    return [{"id": c.id, "title": c.title, "category": c.category,
             "description": c.description, "recommendation": c.recommendation} for c in REGISTRY]
