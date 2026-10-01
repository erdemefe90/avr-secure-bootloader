# AVR Güvenli Bootloader

İngilizce dokümantasyon: [README.md](README.md)

Bu depo ATmega328P için 4 KB bootloader, örnek uygulama ve RS485 üzerinden çalışan PyQt5 flasher içerir. Örnek uygulama `BOOT\n` aldığında `.shared_memory` içindeki 16 bitlik `boot_key` alanına `0xabcd` yazar ve watchdog resetiyle bootloader'a geçer. Uygulama ve bootloader sabit **115200 baud** kullanır. Paylaşılan RAM alanında baud bilgisi bulunmaz.

## Kurulum ve derleme

WSL/Linux:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
make all
make test
```

Windows flasher ortamı:

```powershell
py -3 -m venv .venv-win
.\.venv-win\Scripts\python.exe -m pip install -r requirements.txt
.\.venv-win\Scripts\python.exe Tools\Flasher\main.py
```

Windows ve WSL aynı proje üzerinde çalışacaksa depo `C:\Projects\avr-secure-bootloader` gibi iki taraftan da erişilen bir konumda tutulabilir. WSL karşılığı `/mnt/c/Projects/avr-secure-bootloader` olur. Windows ve WSL için ayrı sanal ortam kullanın: `.venv-win` ve `.venv`.

`make app`, `make bootloader` ve `make package` hedefleri ayrı ayrı çalıştırılabilir. Kök Makefile, App ve Bootloader Makefile'larını include eder. `make all` şu dosyaları üretir:

- `App/Release/App.hex`
- `Bootloader/Release/Bootloader.hex`
- `App/Release/App_encrypted.bin`

İlk derleme `.local/` altında rastgele **geliştirme anahtarları** üretir. Bu dizin Git tarafından yok sayılır. Üretim anahtarlarını depo dışında saklayın ve yollarını açıkça verin:

```sh
make clean
make all DEVICE_KEY_FILE=/secure/device_key.hex SIGNING_KEY_FILE=/secure/signing_private.pem
AVR_TRUSTED_PUBLIC_KEY=/secure/signing_public.pem python Tools/Flasher/main.py
```

`device_key.hex`, 16 baytlık anahtarın tam 32 hexadecimal karakterlik gösterimidir. İmza anahtarı PEM biçiminde Ed25519 private key'dir. Karşılık gelen public key güvenilir flasher dağıtımıyla verilmelidir; firmware paketinin içinden alınmaz. Varsayılan `.local/signing_public.pem` yalnızca geliştirme içindir.

Yeni üretim anahtarları için örnek:

```sh
openssl rand -hex 16 > /secure/device_key.hex
openssl genpkey -algorithm ED25519 -out /secure/signing_private.pem
openssl pkey -in /secure/signing_private.pem -pubout -out /secure/signing_public.pem
chmod 600 /secure/device_key.hex /secure/signing_private.pem
```

`Tools/decrypt_image.py`, paketi test amacıyla doğrulayıp çözer; üretim flash akışının parçası değildir.

## Microchip Studio

`AVR_Bootloader.atsln` içindeki App ve Bootloader projeleri Microchip Studio ile derlenebilir. Aynı linker scriptleri kullanılır. Python 3 ve `requirements.txt` paketleri Studio'nun build ortamında erişilebilir olmalıdır. Bootloader pre-build adımı yerel geliştirme anahtarından `device_key.h` üretir. Üretimde bu adımı ve App paketleme adımını güvenli anahtar yollarına göre düzenleyin.

## Bellek yerleşimi

| Bölge | Adres | Kural |
| --- | --- | --- |
| Uygulama flash | `0x0000–0x6fff` | 28 KB, 128 baytlık sayfalar |
| Image header | `0x0100–0x0143` | 68 bayt, sayfa sınırında başlar |
| Bootloader flash | `0x7000–0x7fff` | `.text` ve yüklenen `.data` toplamı en fazla 4096 bayt |
| Paylaşılan SRAM | `0x800100–0x800101` | `.shared_memory`, yalnızca `boot_key` |
| Normal SRAM | `0x800102` ve sonrası | `.data`, `.bss` ve stack |

Linker scriptleri header ve shared nesne boyutlarını, adresleri, SRAM sınırını ve bootloader flash sınırını `ASSERT` ile denetler. Paketleyici uygulama imajını `0xff` ile tam sayfaya tamamlar. `image_size` bu tamamlanmış uzunluğu taşır. Bootloader imaj boyutunu, donanım kimliğini ve sayfa hizalamasını kontrol eder.

Image header içinde ayrı bir şema sürümü alanı yoktur. Paket formatı yalnızca açık `AVR2` paket magic değeriyle belirlenir. Bootloader ve araçlar modernizasyon öncesindeki header ve paket yerleşimlerini bilinçli olarak reddeder; eski imajlarla geriye uyumluluk desteklenmez.

Packed 68 baytlık header sırasıyla `magic`, `hw_id`, üç yazılım sürümü baytı, `build_num`, `image_size`, 12 baytlık derleme tarihi, 9 baytlık derleme saati, 6 baytlık AVR-GCC sürümü, 12 baytlık AES-CTR nonce ve 16 baytlık tam imaj CMAC tag alanlarını içerir. GUI, seçilen imzalı paket ve algılanan cihaz için bu derleme bilgilerini gösterir.

`Common/image.h`, uygulama ve bootloader arasındaki ortak C arayüzünün tamamıdır. Yalnızca `image_header_t`, `shared_area_t` ve `BOOT_KEY` içerir. Flash haritası, protokol, CRC ve uygulama komutu tanımları bunların sahibi olan proje içinde bulunur.

ATmega328P fuse ayarlarında **BOOTRST programmed** ve **BOOTSZ1:0 = 00** olmalıdır. Böylece 4 KB boot alanı `0x7000` adresinden başlar. Üretimde genel lock bitlerini ve boot lock bitlerini veri sayfasına göre ayarlayın. Bootloader uygulama alanına yazabilmelidir. GUI fuse veya lock biti programlamaz.

## Paket ve doğrulama

`Tools/encrypt_image.py`, uygulama HEX dosyasındaki header'a imaj boyutunu, rastgele 96 bit nonce değerini ve tüm imaj için AES-CMAC etiketini yazar. Gömülü AES-128 cihaz anahtarından ayrı encryption ve MAC anahtarları türetilir. İmaj AES-CTR ile şifrelenir. Her şifreli sayfa; header, sayfa numarası ve ciphertext üzerinde hesaplanan ayrı bir AES-CMAC etiketi taşır.

Paket, GUI'nin sürüm gösterebilmesi için header'ın açık kopyasını içerir. Ed25519 imzası header'ı, bütün şifreli sayfaları ve etiketleri, ayrıca paket uzunluğunu kapsar. Flasher imzası doğrulanmayan paketi kabul etmez. AVR Ed25519 işlemi yapmaz; her sayfanın CMAC'ını kendi cihaz anahtarıyla **flash'a yazmadan önce** doğrular. Uygulamayı başlatmadan önce tüm imajın CMAC'ını tekrar kontrol eder. CRC16 yalnızca RS485 aktarım hatalarını tespit eder; kimlik doğrulama sağlamaz.

Paket biçimi, AES sayaç kodlaması ve protokol komutları `Tools/image_format.py`, `Tools/Flasher/protocol.py` ve `Bootloader/protocol.h` içinde tanımlıdır. Bootloader tekrar gelen aynı sayfayı yeniden yazmadan ACK verir. Kaybolan `FINISH` ACK için aynı isteği kısa süre tekrar kabul eder. NACK kodları paket, durum, boyut, authentication ve imaj hatalarını ayırır. Son UART biti gönderildikten sonra RS485 yönü tekrar receive durumuna döner.

## Flasher kullanımı

WSL/Linux:

```sh
source .venv/bin/activate
python Tools/Flasher/main.py
```

Windows:

```powershell
.\.venv-win\Scripts\python.exe Tools\Flasher\main.py
```

Windows'ta PyQt5 platform plugin yolu uygulama tarafından açıkça ayarlanır; proje yolunda Türkçe veya başka Unicode karakterler bulunsa da GUI açılabilir.

1. **Trusted key / Browse** ile firmware paketlerini doğrulamaya yetkili Ed25519 public key PEM dosyasını seçin. Geçersiz veya farklı türde anahtar reddedilir. Anahtar değiştiğinde seçili firmware otomatik olarak yeniden doğrulanır; doğrulama başarısızsa Flash devre dışı kalır. Kontrollü üretim ortamında `AVR_TRUSTED_PUBLIC_KEY` ile varsayılan anahtarı verin ve operatörün seçebileceği public key dosyalarını sınırlandırın.
2. Seri porta bağlanın. Uygulama çalışıyorsa **Go Bootloader**, `BOOT\n` gönderir. GUI bootloader header'ı alınca geçişi doğrular.
3. **Go Application** yalnızca bootloader algılandığında etkindir. Reset komutunu gönderir ve örnek uygulamanın periyodik `Hello World!!` mesajıyla geçişi doğrular. Beklenen cevap gelmezse timeout gösterilir.
4. İmzalı `.bin` paketini seçin. İmza doğrulandıktan sonra sürüm, donanım kimliği ve boyut gösterilir.
5. **Flash** düğmesine basın. Aynı veya daha eski sürüm varsayılan olarak kilitlidir. **Force** yalnızca bu GUI sürüm kuralını aşar; imza, donanım kimliği veya AVR CMAC kontrollerini aşmaz. Bu GUI kuralı cihaz tarafında güvenli anti-rollback sayacı değildir.

## Güvenlik ve güç kesintisi sınırları

Eski revizyonlarda AES anahtarı ve RSA private key Git tarafından takip edilmişti. Bu anahtarlar Git geçmişinden erişilebilir ve üretimde kullanılmamalıdır. Yeni üretim anahtarları oluşturup cihazları yeniden provision edin. Yeni paket biçimi ve anahtar eski bootloader ile uyumlu değildir; ilk geçiş ISP programlayıcı gerektirir. Bootloader içindeki AES anahtarını okumaya karşı doğru fuse ve lock bitlerini yapılandırın.

ATmega328P'de ikinci uygulama bankası yoktur. Doğrulanmamış sayfa flash'a yazılmaz; fakat geçerli güncelleme başladıktan sonra güç kesilirse eski uygulama kısmen silinmiş olabilir. Bootloader geçersiz imajı başlatmaz ve yeni güncelleme bekler. Fiziksel erişim, signing private key'in veya cihaz AES anahtarının ele geçirilmesi bu tasarımın güvenlik sınırları dışındadır.
