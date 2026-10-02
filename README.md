# F5 WAF Healthcheck

F5 BIG-IP (AWAF/ASM) cihazlarındaki **partition bazlı müşteri yapılandırmalarını** iControl REST üzerinden
salt-okunur tarar. Güvenlik açığına veya durum takibinin kaybolmasına yol açan kuralları bulur ve
HTML / Excel / JSON / CSV olarak raporlar. İki şekilde kullanılabilir: komut satırı (zamanlanmış görev)
ve REST API.

## Kontroller

| ID | Kontrol | Önem |
|----|---------|------|
| WAF-001 | Policy transparent modda (süreye göre) | MEDIUM → HIGH (≥14 g) → CRITICAL (≥60 g) |
| WAF-002 | Policy inactive ama VS'e atanmış | HIGH |
| WAF-003 | Hiçbir VS'e bağlı olmayan policy | LOW |
| WAF-004 | Readiness süresi dolmuş, staging'de bekleyen imzalar | HIGH (blocking) / MEDIUM |
| WAF-005 | Signature set block kapalı | HIGH / CRITICAL (alarm da kapalıysa) |
| WAF-006 | Kritik violation engellenmiyor / loglanmıyor | HIGH / MEDIUM |
| WAF-007 | Eşik üstü devre dışı imza | MEDIUM |
| WAF-008 | Learning riskli (transparent+kapalı, blocking+otomatik) | MEDIUM / LOW |
| WAF-009 | Trust XFF açık | LOW |
| WAF-010 | Apply edilmemiş policy değişikliği | MEDIUM |
| WAF-011 | Policy okunamadı, kontrol yapılamadı | MEDIUM |
| LTM-001 | VS offline / unknown / disabled | HIGH / LOW / INFO |
| LTM-002 | Pool: tüm üyeler down, çoğunluk down, boş pool, monitor yok | HIGH / MEDIUM / LOW |
| LTM-003 | WAF policy'si olmayan VS (80 portu hariç, ayarlanabilir) | HIGH (HTTP) / MEDIUM (L4) |
| LTM-004 | WAF'lı VS'de security log profili yok | MEDIUM |
| LTM-005 | Pool / iRule / policy'si olmayan VS | LOW |
| CERT-001 | Client-SSL sertifikası dolmuş / dolmak üzere | CRITICAL / HIGH / MEDIUM |
| DEV-001 | Attack signature (ASU) paketi eski | MEDIUM / HIGH |
| DEV-002 | HA config sync bozuk | MEDIUM |
| DEV-003 | Cihaz verisi eksik toplandı | MEDIUM |

`python cli.py checks` komutu kataloğun tamamını açıklamalarıyla birlikte listeler.

### Durum takibi
- Her tarama `state/*.db` (SQLite) dosyasına kaydedilir. Bulgular **YENİ / DEVAM EDEN** olarak etiketlenir. Önceki taramada olup artık görülmeyenler **KAPANAN** listesine düşer.
- Transparent süresi iki kaynaktan hesaplanır: cihazdaki son policy değişikliği (`versionDatetime`) ve aracın bu durumu ilk gördüğü tarih. Büyük olan kullanılır. ASM, "transparent'a ne zaman geçildi" bilgisini doğrudan tutmadığı için bu değer bir **alt sınırdır**. Araç düzenli çalıştıkça daha doğru sonuç verir.
- Kısmi taramalar (tek cihaz ya da tek partition) diğer partition'ların geçmişini bozmaz.

## Kurulum
```powershell
cd D:\Projeler\WafHealthcheck
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy config.example.yaml config.yaml
```

### BIG-IP kullanıcısı
Her cihazda, tüm partition'larda **Auditor** (veya en az Guest + ASM okuma) rolüne sahip salt-okunur bir kullanıcı oluşturun:
```
tmsh create auth user waf_audit password '***' partition-access add { all-partitions { role auditor } } shell none
```
Araç yalnızca GET isteği yapar. Tek istisna, kendi login token'ının ömrünü uzatmak için gönderdiği PATCH isteğidir.

### Kimlik bilgileri
Şifreleri config dosyasına yazmayın, ortam değişkeninden verin:
```powershell
$env:F5_USER="waf_audit"; $env:F5_PASS="***"; $env:F5WAF_API_KEY="uzun-rastgele-anahtar"
```

## Kullanım

```powershell
# Cihaz olmadan demo (3 sahte cihaz, ~23 müşteri)
python cli.py scan -c config.demo.yaml

# Gerçek tarama
python cli.py scan -c config.yaml
python cli.py scan -c config.yaml --device waf02 --partition "P_BETA*"
python cli.py scan -c config.yaml --fail-on HIGH      # HIGH+ bulgu varsa exit 2 (izleme/CI için)

# API
python cli.py serve -c config.yaml --port 8080        # http://sunucu:8080/docs
```

### API uç noktaları
| Metot | Yol | Açıklama |
|---|---|---|
| POST | `/api/scans` | `{"devices":["waf01"], "partitions":["P_ACME"]}` (ikisi de opsiyonel), 202 döner |
| GET | `/api/scans` | Tarama geçmişi |
| GET | `/api/scans/{id\|latest}` | Özet, cihaz durumu, partition risk sıralaması |
| GET | `/api/scans/{id\|latest}/findings` | `?device=&partition=&severity=&min_severity=HIGH&check_id=&status=NEW` |
| GET | `/api/scans/{id\|latest}/report.{html\|xlsx\|json\|csv}` | Rapor indir |
| GET | `/api/partitions/{partition}` | Bir müşterinin son durumu |
| GET | `/api/checks` | Kontrol kataloğu |
| GET | `/api/health` | Sağlık |

`api.keys` doluysa her istekte `X-API-Key` başlığı gerekir.

### Zamanlama (Windows Görev Zamanlayıcı)
```powershell
schtasks /create /tn "WAF Healthcheck" /sc daily /st 07:30 ^
  /tr "D:\Projeler\WafHealthcheck\.venv\Scripts\python.exe D:\Projeler\WafHealthcheck\cli.py scan -c D:\Projeler\WafHealthcheck\config.yaml"
```

## Yapılandırma notları
- **`partition_overrides`**: Eşikleri müşteri bazında değiştirir. Örneğin yeni müşteriye 45 günlük transparent süresi tanınabilir.
- **`suppressions`**: Kabul edilmiş riskleri tanımlar. `check/device/partition/object` alanları joker (`*`) destekler. `until` tarihi geçince istisna kendiliğinden düşer ve bulgu yeniden aktif olur. İstisnalı bulgular raporda ayrı bir bölümde gösterilir.
- **`customers`**: Partition adını müşteri adıyla eşler.
- **`no_waf_exempt_ports`**: LTM-003'te raporlanmayacak portlar. Varsayılan `[80]`: bu VS'ler yalnızca redirect iRule'u ile HTTPS'e yönlendirme yapıyor. `no_waf_include_non_http: true` iken HTTP profili olmayan WAF'sız VS'ler (L4 / SSL passthrough) MEDIUM olarak ayrıca listelenir.
- **`only_waf_partitions`**: `true` ise LTM-003 (WAF'sız HTTP VS) kontrolü yalnızca WAF policy'si bulunan partition'larda çalışır. WAF hizmeti almayan partition'lar böylece gürültü üretmez.
- **`policy_workers`**: ASM REST yavaştır. Çok sayıda policy varsa 4–6 arası bir değer yeterlidir; daha yüksek değerler cihazın control-plane'ini yorar.

## Yeni kontrol eklemek
`f5waf/checks.py` içine şu şekilde bir fonksiyon eklemeniz yeterli:
```python
@check("WAF-012", "Başlık", "Kategori", "Açıklama", "Öneri")
def chk_ornek(chk, ctx):
    for p in ctx.snap.policies:
        if ...:
            yield ctx.finding(chk, "HIGH", _pol_partition(p), "asm-policy", p.full_path, "detay")
```

## Sahada doğrulanması gerekenler
Aşağıdaki alanlar sürümden sürüme farklılık gösterebilir. İlk gerçek taramadan sonra JSON rapordaki değerleri kontrol edin:
- `/mgmt/tm/live-update/asm-attack-signatures/installations`: ASU tarihi dosya adından okunur. Okunamazsa DEV-001 LOW "tarih okunamadı" bulgusu üretir.
- `isModified` (WAF-010) ve `policy-builder.learningMode` (WAF-008): v15/16/17 sürümlerinde mevcuttur.
- LTM-003 kontrolü, VS–policy eşlemesini ASM policy'nin `virtualServers` alanından yapar (v14+ LTM policy ile atanan policy'ler dahil).

## Proje yapısı
```
cli.py                 komut satırı
f5waf/client.py        iControl REST istemcisi (token, sayfalama, retry)
f5waf/collector.py     cihazdan veri toplama, partition filtreleme
f5waf/checks.py        kurallar
f5waf/scanner.py       orkestrasyon, istisnalar, yeni/kapanan hesabı
f5waf/state.py         SQLite durum deposu
f5waf/reporters/       html, xlsx, json, csv
f5waf/api.py           FastAPI
f5waf/mock.py          demo/test için sahte BIG-IP
tests/                 pytest (python -m pytest -q)
```
