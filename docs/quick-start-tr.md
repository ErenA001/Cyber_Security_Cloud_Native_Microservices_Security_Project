# CloudGuard AI 2.0 - Turkce Hizli Kurulum

## Gerekenler

- Docker Desktop ve `docker compose`
- Python 3.10 veya ustu
- NVIDIA Build hesabindan API key (canli AI icin)
- Port 8080'in bos olmasi

## Ilk kurulum

1. Terminalde proje klasorune girin.
2. Ilk kez kuruyorsaniz gizli anahtarlari ve yonetici sifresini olusturun:

   ```bash
   python3 scripts/setup.py
   ```

3. Terminalde yazan `admin` sifresini guvenli bir yere kaydedin.
4. `.env` dosyasini acin ve `NVIDIA_API_KEY=` satirina kendi NVIDIA API anahtarinizi ekleyin.
5. Uygulamayi derleyip baslatin:

   ```bash
   docker compose up --build -d
   ```

6. `docker compose ps` ciktisinda `edge` servisinin `127.0.0.1:8080->8080/tcp` portunu gosterdigini dogrulayin. Tarayicidan `http://127.0.0.1:8080` adresini acin. Kullanici adi `admin`, sifre ilk kurulumda olusturulan sifredir.

## 1.0 / 2.0.0 surumunden 2.0.1 surumune gecis

- Eski proje klasorunun yedegini alin.
- Yeni 2.0.1 ZIP dosyasini ayri bir klasore cikarin.
- Eski proje klasorundeki `.env` dosyasini yeni proje klasorune kopyalayin. Boylece NVIDIA API anahtari, JWT anahtari ve mevcut yonetici hesabiniz korunur.
- Yeni klasorde `docker compose up --build -d` calistirin.
- `docker compose down -v` komutunu kullanmayin. Bu komut kullanici, olay ve diger kalici verileri siler.

## Kontrol

`docker compose ps` ciktisinda host portunun yalnizca `edge` servisinde gorunmesi gerekir. `gateway`, `auth`, `ai` ve `monitor` host portu yayinlamaz.

```bash
python3 scripts/doctor.py
sh scripts/run_unit_tests.sh
python3 tests/security_regression.py
python3 tests/resilience_test.py
```

Guvenlik regresyon testi yonetici sifresini terminalde sorar ve sonucunu Security Lab rapor alanina kaydeder. Resilience testi az sayida saglik istegi gonderir; container durdurmaz ve stres testi yapmaz.

## Gercek Trivy imaj taramasi

```bash
python3 scripts/scan_local_images.py
```

Script yonetici sifresini sorar, yerel Docker imajlarini `docker save` ile arsivler ve Trivy tarayicisini izole bir Docker container'i icinde calistirir. Docker socket tarayici container'ina baglanmaz. Sonuclar Security Lab ekraninda gorunur.

## Orijinal v1 / guclendirilmis v2 tarama karsilastirmasi

Orijinal kod `baseline/` klasorunde yalnizca inceleme ve imaj taramasi icin tutulur. Guvensiz servisleri calistirmayin.

```bash
python3 scripts/build_baseline_images.py
python3 scripts/scan_local_images.py --images cloudguard-baseline/auth:original,cloudguard-baseline/ai:original,cloudguard-baseline/logger:original,cloudguard-baseline/gateway:original
python3 scripts/scan_local_images.py
```

Ayni Trivy surumuyle once orijinal imajlari, sonra guclendirilmis imajlari tarayin. Ham JSON raporlari `reports/trivy/` altina kaydedilir; secret eslesmeleri ve kaynak satirlari rapor kaydindan once maskelenir.

## AI analizi ve rapor

- AI Analyst sayfasinda NVIDIA NIM ile sohbet edin.
- Sohbet gecmisi kullaniciya gore yerel SQLite veritabaninda saklanir.
- Analyze latest events, son olaylari ve Trivy raporlarini AI'ya analiz ettirir.
- Security Lab sayfasindan JSON guvenlik raporunu indirin.

## Veriyi koruma

Calisan SQLite veritabanlarini tutarli sekilde yedeklemek icin:

```bash
python3 scripts/backup_data.py
```

Yedekler `backups/` klasorune kaydedilir; kullanici hash'leri, sohbet gecmisi ve guvenlik kayitlari icerir. Bu klasoru gizli tutun ve Git'e eklemeyin.

- `docker compose down`: uygulamayi durdurur, veriyi korur.
- `docker compose up -d`: uygulamayi yeniden baslatir.
- `docker compose down -v`: tum kalici verileri siler. Yalnizca sifirdan baslamak istediginizde kullanin.

## Onemli sinirlar

Bu proje egitim ve yerel demonstrasyon icindir. AI onerileri danisman niteligindedir. Security Lab butonlari sentetik olay kaydeder; gercek saldiri yapmaz. Trivy taramasi imaj icerigini tarar; canli sistemin aciklarini kesin olarak kanitlamaz. NVIDIA'ya gonderilen promptlar NVIDIA'nin barindirilan API'sinde islenir. Gizli bilgi, sifre veya kisisel veri girmeyin.
