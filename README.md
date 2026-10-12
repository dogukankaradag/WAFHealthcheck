# F5 WAF Healthcheck

F5 BIG-IP (AWAF/ASM) cihazlarındaki **partition bazlı müşteri yapılandırmalarını** iControl REST üzerinden
salt-okunur tarar. Güvenlik açığına veya durum takibinin kaybolmasına yol açan kuralları bulur ve
HTML / Excel / JSON / CSV olarak raporlar. İki şekilde kullanılabilir: **web arayüzü** (FirewallAudit / fwcheck
ile aynı mantık: kullanıcı girişi, manuel tarama, bulgu iş akışı, geçmiş) ve komut satırı.

Otomatik / zamanlanmış tarama yoktur; taramalar arayüzdeki **▶ Tara** düğmesiyle (veya CLI ile) manuel başlatılır.

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

### ASM Policyler
Tüm cihazlardaki WAF (ASM) policy'lerinin envanteri; arayüzde **ASM Policyler** menüsünde, Excel'de "ASM Policyler" sayfasında.
- Toplam policy sayısı, Blocking / Transparent dağılımı ve cihaz bazında (cihaz adı + IP) kırılım; hepsi tıklanarak filtrelenir.
- Her policy için bağlı virtual server'lar (hedef IP:port ile), cihaz ve IP, son değişiklik tarihi, transparent süresi, learning modu, staging'deki ve devre dışı imza sayısı, açık bulgu sayısı.
- Filtreler: mod, cihaz, VS'e bağlı / bağlı değil, pasif, Apply bekleyen, açık bulgusu olan; arama policy, VS, müşteri ve IP'de çalışır.
- Cihaz IP'si `config.yaml` içindeki `host` değeridir.

### DoS Protection ve Bot Protection envanteri
Bulgu değil envanterdir. Arayüzde **DoS Protection** ve **Bot Protection** menülerinde, Excel raporunda da aynı adlı sayfalarda listelenir.
- Her virtual server için bağlı DoS profili (uygulama/L7 algılamaları ve modları) ve Bot Defense profili (Blocking / Transparent, şablon).
- **Kullananlar / Kullanmayanlar / Tümü** görünümü. "Korunması beklenen" VS = HTTP profili olan, yönlendirme portunda (`no_waf_exempt_ports`, varsayılan 80) olmayan VS.
- v14.1 öncesi sürümlerde DoS profili içinde tanımlanan bot defense de Bot Protection altında gösterilir.

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
$env:F5_USER="waf_audit"; $env:F5_PASS="***"
$env:F5WAF_ADMIN_PASSWORD="ilk-admin-parolasi"   # opsiyonel, yalnızca ilk açılışta kullanılır
$env:F5WAF_API_KEY="uzun-rastgele-anahtar"       # opsiyonel, otomasyon için
```

## Web arayüzü

**En kolay yol (fwcheck ile aynı):**
```powershell
.\.venv\Scripts\Activate.ps1
python run.py                  # config.yaml varsa onu, yoksa demo config'i kullanır → http://localhost:4467
python run.py config.demo.yaml # demo
python run.py --port 4500      # farklı port
```

```bash
cd /opt/waf-healthcheck
set -a; . ./.env; set +a                       # F5_USER, F5_PASS (+ isteğe bağlı F5WAF_ADMIN_PASSWORD)
.venv/bin/python cli.py serve -c config.yaml   # varsayılan port 4467  →  http://<sunucu>:4467
```
fwcheck 4466 portunda çalıştığı için WAF Healthcheck varsayılan olarak **4467** kullanır (`--port` ile değiştirilebilir).

**İlk giriş:** İlk açılışta `admin` kullanıcısı oluşturulur. Parola `F5WAF_ADMIN_PASSWORD` ortam değişkeninden alınır;
değişken yoksa rastgele üretilip başlangıç loguna yazılır (`journalctl -u waf-healthcheck -n 50`).
Parola unutulursa: `python cli.py user passwd admin`.

| Ekran | İçerik |
|---|---|
| Üst kartlar | Açık bulgu, Kritik/Yüksek/Orta/Düşük/Bilgi, 🆕 Yeni, ✅ Çözüldü (sonradan değişenler 🔄) — tıklayınca filtreler |
| Sol menü | Cihaz → partition ağacı, açık bulgu rozetleri, arama; tıklayınca o cihaz/partition'a filtreler |
| 📋 Bulgular | Arama, önem, kategori, iş durumu, kontrol filtreleri; satıra tıklayınca detay + kanıt + öneri |
| 📊 Partition Risk | Müşteri bazlı risk skoru sıralaması |
| 🖥️ Cihaz Durumu | Sürüm, partition/VS/policy/pool sayısı, tarama süresi, bağlantı hataları |
| ▶ Tara (admin) | Cihaz seçimi + opsiyonel partition filtresi (`P_ACME, P_BETA*`); canlı, cihaz bazlı ilerleme |
| 📋 Geçmiş | Tüm taramalar (başlatan, kapsam, yeni/düzeltilen); eski taramayı görüntüleme, HTML/Excel indirme |
| 👥 Kullanıcılar (admin) | Kullanıcı ekleme, rol, pasif yapma, parola değiştirme |

**Roller:** `admin` tarama başlatır, bulgu durumunu değiştirir ve kullanıcıları yönetir. `readonly` görüntüler ve rapor indirir.

**Bulgu iş akışı:** Açık → Onaylandı → İşlemde → Çözüldü. Yorum (ör. CHG numarası) ve sorumlu eklenebilir. Durum
taramalar arasında kalıcıdır. "Çözüldü" işaretlenen bir bulgunun nesnesi sonraki taramalarda değişirse
🔄 *Sonradan Değişti* olarak işaretlenir. Cihazda gerçekten düzeltilen ve taramada artık görülmeyen bulgular
"🛠 Düzeltilen" filtresinde listelenir.

## Komut satırı

```bash
python cli.py scan -c config.demo.yaml                          # cihazsız demo
python cli.py scan -c config.yaml
python cli.py scan -c config.yaml --device waf02 --partition "P_BETA*"
python cli.py scan -c config.yaml --fail-on HIGH                # HIGH+ bulgu varsa exit 2

python cli.py user list
python cli.py user add ahmet --role readonly --full-name "Ahmet Y."
python cli.py user passwd admin
```
CLI ile yapılan taramalar da aynı veritabanına yazılır ve arayüzde görünür.

### API
Arayüzün kullandığı uç noktalar `http://<sunucu>:4467/api/docs` adresinde listelenir. Otomasyon için
`config.yaml → api.keys` tanımlanırsa `X-API-Key` başlığıyla (admin yetkisinde) erişilebilir:
```bash
curl -X POST -H "X-API-Key: $F5WAF_API_KEY" -H "Content-Type: application/json" \
     -d '{"device_ids":["waf01"],"partitions":"P_ACME"}' http://localhost:4467/api/scan
curl -H "X-API-Key: $F5WAF_API_KEY" "http://localhost:4467/api/findings?severity=CRITICAL"
```

### Servis olarak çalıştırma (systemd)
`/etc/systemd/system/waf-healthcheck.service`
```ini
[Unit]
Description=WAF Healthcheck
After=network-online.target

[Service]
WorkingDirectory=/opt/waf-healthcheck
EnvironmentFile=/opt/waf-healthcheck/.env
ExecStart=/opt/waf-healthcheck/.venv/bin/python cli.py serve -c config.yaml --port 4467
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now waf-healthcheck
journalctl -u waf-healthcheck -n 50     # ilk admin parolası burada
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
- `/mgmt/tm/security/dos/profile?expandSubcollections=true`: uygulama DoS modu `applicationReference.items[].tpsBased/stressBased/behavioralDosDetection` altındaki `mode` veya `operationMode` alanından okunur. AFM/ASM DoS provision değilse endpoint 404 döner ve envanter boş kalır.
- `/mgmt/tm/security/bot-defense/profile`: `enforcementMode` alanı (v14.1+).
- `/mgmt/tm/live-update/asm-attack-signatures/installations`: ASU tarihi dosya adından okunur. Okunamazsa DEV-001 LOW "tarih okunamadı" bulgusu üretir.
- `isModified` (WAF-010) ve `policy-builder.learningMode` (WAF-008): v15/16/17 sürümlerinde mevcuttur.
- LTM-003 kontrolü, VS–policy eşlemesini ASM policy'nin `virtualServers` alanından yapar (v14+ LTM policy ile atanan policy'ler dahil).

## Proje yapısı
```
cli.py                 komut satırı
f5waf/client.py        iControl REST istemcisi (token, sayfalama, retry)
f5waf/collector.py     cihazdan veri toplama, partition filtreleme
f5waf/checks.py        kurallar
f5waf/protections.py   DoS / Bot Protection envanteri
f5waf/scanner.py       orkestrasyon, istisnalar, yeni/kapanan hesabı
f5waf/state.py         SQLite durum deposu
f5waf/reporters/       html, xlsx, json, csv
f5waf/api.py           FastAPI (web arayüzü backend'i)
f5waf/auth.py          kullanıcı girişi, roller, oturum token'ı
f5waf/web/index.html   web arayüzü (tek sayfa)
f5waf/mock.py          demo/test için sahte BIG-IP
tests/                 pytest (python -m pytest -q)
```
