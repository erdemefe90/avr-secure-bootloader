# AVR Güvenli Bootloader

İngilizce dokümantasyon: [README.md](README.md)

Katkı ve coding-agent çalışma rehberi: [AGENTS.md](AGENTS.md)

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

Proje kökü `avr-secure-bootloader/` dizinidir; bu ortamda `/root/projects/avr-secure-bootloader` konumundadır. Yolları gerçek Git köküne göre çözümleyin; sabit bir Windows/WSL yolu varsaymayın. Windows ve WSL için ayrı sanal ortam kullanın: `.venv-win` ve `.venv`.

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
| Bootloader kodu ve yüklenen veri | `0x7000–0x7f5f` | Metadata alanına taşamaz |
| Bootloader bilgisi | `0x7f60–0x7f79` | Packed 26 baytlık `boot_info_t` |
| Ayrılmış seri numarası silme sayfası | `0x7f80–0x7fff` | Kod veya yüklenen veri bulunmaz |
| Seri numarası | `0x7ff0–0x7fff` | 16 baytlık C string: en fazla 15 UTF-8 baytı + NUL; varsayılan değer `0xff` |
| Paylaşılan SRAM | `0x800100–0x800101` | `.shared_memory`, yalnızca `boot_key` |
| Normal SRAM | `0x800102` ve sonrası | `.data`, `.bss` ve stack |

Linker scriptleri header ve shared nesne boyutlarını, adresleri, SRAM sınırını ve bootloader flash sınırını `ASSERT` ile denetler. Boot alanının tamamı `0x7000–0x7fff` (4096 bayt) olarak kalır; yüklenen bayt hesabına `.text`, yüklenen `.data`, `.boot_info` ve `.serial_number` dahildir. Ayrı linker bölgeleri ve boyut/adres kontrolleri, kodun veya verinin metadata ve seri numarası silme sayfasına yerleşmesini engeller. App linker uygulama yüklerini zaten `0x7000` öncesinde sınırlar. Paketleyici uygulama imajını `0xff` ile tam sayfaya tamamlar. `image_size` bu tamamlanmış uzunluğu taşır. Bootloader imaj boyutunu, donanım kimliğini ve sayfa hizalamasını kontrol eder.

Image header içinde ayrı bir şema sürümü alanı yoktur. Paket formatı yalnızca açık `AVR3` paket magic değeriyle belirlenir. Yeni header sırası `AVR2` ve modernizasyon öncesindeki yerleşimlerle uyumsuzdur. App yeniden derlenip paketlenmeli ve `AVR3` paketlerinden önce uyumlu bootloader ISP ile yüklenmelidir.

Packed 68 baytlık header sırasıyla `magic`, `hw_id`, üç yazılım sürümü baytı, `build_num`, 12 baytlık derleme tarihi, 9 baytlık derleme saati, 6 baytlık AVR-GCC sürümü, `image_size`, 12 baytlık AES-CTR nonce ve 16 baytlık tam imaj CMAC tag alanlarını içerir. GUI, seçilen imzalı paket ve algılanan cihaz için bu derleme bilgilerini gösterir.

`Common/image.h`, uygulama ve bootloader arasındaki ortak C arayüzünün tamamıdır. `image_header_t`, `boot_info_t`, `shared_area_t`, `BOOT_KEY` ve bootloader bilgisi/seri numarası bayt adresleri ile boyutlarını içerir. Diğer flash haritası, protokol, CRC ve uygulama komutu tanımları bunların sahibi olan proje içinde bulunur. Header içinde derleme tarihi/saati 11/23, `image_size` 38, nonce 40 ve CMAC etiketi 52 bayt ofsetinde başlar; toplam boyut 68 bayt kalır.

ATmega328P fuse ayarlarında **BOOTRST programmed** ve **BOOTSZ1:0 = 00** olmalıdır. Böylece 4 KB boot alanı `0x7000` adresinden başlar. Genel ISP lock bitlerini gereken harici erişim korumasına göre ayarlayın. Bootloader uygulamayı CMAC için okuyabilsin diye BLB02; seri güncellemeler kullanılacaksa BLB01 programlanmamış kalmalıdır. App boot metadata alanını okuyabilsin diye BLB12 programlanmamış kalmalıdır; bu aynı zamanda uygulamanın boot kodu/anahtar alanını okumasına izin verir. BLB11, metadata okumalarını koruyarak boot alanına yazmayı engelleyebilir. GUI/CLI bütün fuse ve lock bitlerini okur; bootloader SPM komutuyla yalnızca LB2/LB1 programlanabilir. BLB0/BLB1 ve fuse yazımı ISP; kilit açma ISP chip erase gerektirir. Fuse ve BLB korumalarını son LB korumasından önce ISP üzerinden ayarlayın. Bkz. [ATmega328P veri sayfası](https://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-7810-Automotive-Microcontrollers-ATmega328P_Datasheet.pdf), bölüm 26–27, ve [AVR-LibC boot araçları](https://www.nongnu.org/avr-libc/user-manual/group__avr__boot.html).

## Bootloader bilgisi ve seri numarası

`BOOT_INFO_ADDRESS` (`0x7f60`), packed `boot_info_t` alanının adresidir: sırasıyla üç sürüm baytı, 16 bitlik `build_num`, `compile_date[12]` ve `compile_time[9]`. Bootloader şu anda `1.1.0+1` sürümü ve kendi derleme tarih/saatiyle başlatılır. `SERIAL_NUMBER_ADDRESS` (`0x7ff0`), en fazla 15 UTF-8 baytı ve sonlandırıcı NUL içeren 16 baytlık C string alanının adresidir. `BOOT_INFO_SIZE` ve `SERIAL_NUMBER_SIZE` değerleri 26 ve 16'dır. Bunlar SRAM adresleri değil, **flash bayt adresleridir**; uygulama bootloader sembollerini link etmeden okuyabilir:

```c
#include <avr/pgmspace.h>
#include "image.h"

boot_info_t info;
char serial[SERIAL_NUMBER_SIZE];
memcpy_P(&info, (const void *)BOOT_INFO_ADDRESS, sizeof(info));
memcpy_P(serial, (const void *)SERIAL_NUMBER_ADDRESS, sizeof(serial));
serial[SERIAL_NUMBER_SIZE - 1] = '\0'; /* eski/silinmiş veride de sınır korunur */
if ((uint8_t)serial[0] == 0xff) serial[0] = '\0';
```

App kaynakları ve mevcut linker scripti değiştirilmemiştir. Ortak header'ın yeni sırası App yeniden derlendiğinde uygulanır. Seri numarasını aşağıdaki ayrı RS485 aracıyla veya ISP programlamadan önce bootloader HEX'in bir kopyasında yalnızca `0x7ff0–0x7fff` baytlarını en fazla 15 UTF-8 baytı, NUL ve sıfır dolgusu ile değiştirerek kaydedin. Özellikle gömülü cihaz anahtarı ve boot metadata dahil diğer bütün HEX baytlarını koruyun. Varsayılan HEX bu alanda `0xff` içerir. Normal imzalı uygulama güncellemeleri boot alanına veya seri numarası sayfasına yazmaz. ISP chip erase seri numarasını siler; bootloader yeniden kurulurken tekrar kaydedin. Bootloader HEX dosyaları cihaz anahtarını içerir ve provision sırrı olarak saklanmalıdır.

### Ayrı seri numarası yazma aracı

Seri portu boşaltmak için flasher GUI bağlantısını kapatıp çalıştırın:

```sh
python Tools/write_serial.py --port /dev/ttyUSB0 --serial "DEVICE-001"
```

Windows:

```powershell
.\.venv-win\Scripts\python.exe Tools\write_serial.py --port COM5 --serial "DEVICE-001"
```

`--serial`, **en fazla 15 baytlık**, boş olmayan ve yazdırılabilir UTF-8 metin kabul eder; 16. bayt sonlandırıcı NUL için ayrılmıştır. `DEVICE-001` gibi kısa bir değer girilebilir; yazma aracı NUL ve sıfır dolgusunu otomatik ekler. Sınır karakter değil, kodlanmış bayt sayısıdır; metin içindeki NUL/kontrol karakterleri ve uzun girişler kesilmeden reddedilir. Okuyucular ilk NUL'a kadar olan metni gösterir; elle 16 bayta tamamlamak gerekmez. Tümü `0xff` olan flash alanı kaydedilmemiş seri numarası anlamında kalır. Kayıtlı seri numarasını değiştirmek için `--replace` gerekir. Seri numarası zaten aynıysa flash yazılmadan doğrulanır. Araç 115200 baud kullanır, 0,5 saniye bootloader paketlerini dinler; algılanmazsa bir kez `BOOT\n` gönderir ve HEADER/INFO paketleriyle girişi doğrular; yazmadan önce güncel seri/kilit durumunu okur. Timeout veya bozuk paketlerde aynı istek tekrar gönderilir. Başarı için ACK ve seri numarasının geri okunup eşleşmesi gerekir; hata durumunda çıkış kodu 1'dir. İşlemden sonra cihaz bootloader modunda kalır. Araç Qt gerektirmez; firmware, fuse, lock veya reset komutları göndermez.

Önce uyumlu bootloader ISP ile yüklenmelidir. Boot alanı yazma koruması (BLB11), seri numarası değişimini engeller: seri numarasını bu kilidi uygulamadan **önce** kaydedin. GUI'ye tekrar bağlandığınızda kayıtlı seri numarası metni **Bootloader info → Serial number** alanında görünür. Ana flasher seri numarasını gösterir; yazma işlemi bu ayrı araca aittir.

`CMD_SERIAL` (`0xba`), beklenen mevcut seri numarasını ve yeni seri numarasını (16'şar bayt) taşır; ACK/NACK sıra numarası `0xfffd` değeridir. Bootloader mevcut seri değişmişse, firmware aktarımı/FINISH bekleme süresi aktifse, uzunluk hatalıysa veya boot yazma kilidi varsa isteği reddeder. Zaten yazılmış aynı değer tekrar geldiğinde yeniden yazmadan ACK verir. Yalnızca `0x7f80` adresindeki ayrılmış sayfa silinir/yazılır; ilk 112 bayt korunur, son 16 bayt NUL ile sonlandırılmış seri alanıyla değiştirilir ve ACK öncesinde 128 baytın tamamı doğrulanır. Bootloader yeni alanın ilk baytı boşsa veya son baytı sıfır değilse isteği reddeder. İstek flash adresi taşımaz. Seri kaydetme kriptografik kimlik doğrulama yerine CRC kullanır; seri servis erişimini sınırlandırın. Güç kesilmesi seri numarasını kaybettirebilir fakat bu komut App, boot kodu veya boot metadata alanını silemez.

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

Windows'ta PyQt5 platform plugin yolu uygulama tarafından açıkça ayarlanır; proje yolunda Türkçe veya başka Unicode karakterler bulunsa da GUI açılabilir. QApplication oluşturulmadan önce ayrı AppUserModelID atanır; uygulama/pencere ve Browse simgeleri main.py yanındaki dosyalardan mutlak yolla yüklenir. Böylece farklı çalışma dizininden başlatıldığında AVR simgesi kullanılır ve Python ile gruplanmaz. Bkz. [Microsoft başlangıç koşulu](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-setcurrentprocessexplicitappusermodelid). Konsol açmadan GUI başlatmak için `.\.venv-win\Scripts\pythonw.exe Tools\Flasher\main.py`; çıktıyı görmek için CLI komutlarında python.exe kullanın.

1. **Trusted key / Browse** ile firmware paketlerini doğrulamaya yetkili Ed25519 public key PEM dosyasını seçin. Geçersiz veya farklı türde anahtar reddedilir. Anahtar değiştiğinde seçili firmware otomatik olarak yeniden doğrulanır; doğrulama başarısızsa Flash devre dışı kalır. Kontrollü üretim ortamında `AVR_TRUSTED_PUBLIC_KEY` ile varsayılan anahtarı verin ve operatörün seçebileceği public key dosyalarını sınırlandırın.
2. Seri porta bağlanın. Uygulama çalışıyorsa **Go Bootloader**, `BOOT\n` gönderir. GUI bootloader header'ı alınca geçişi doğrular.
3. **Go Application** yalnızca bootloader algılandığında etkindir. Reset komutunu gönderir, önbellekteki cihaz bilgilerini temizler ve uygulamayı başlatma isteğinin gönderildiğini bildirir. Uygulama çıktısını beklemez veya yorumlamaz. Bootloader'a giriş isteklerinde ise bootloader header'ı beklenmeye devam edilir; gelmezse timeout bildirilir.
4. İmzalı `.bin` paketini seçin. İmza doğrulandıktan sonra sürüm, donanım kimliği ve boyut gösterilir.
5. **Flash** düğmesine basın. Aynı veya daha eski sürüm varsayılan olarak kilitlidir. **Force** yalnızca bu GUI sürüm kuralını aşar; imza, donanım kimliği veya AVR CMAC kontrollerini aşmaz. Bu GUI kuralı cihaz tarafında güvenli anti-rollback sayacı değildir. Flash için güncel bootloader durumunda uygulama okuma/yazma izinleri de gereklidir; Force donanım kilitlerini aşamaz. Aktarım sırasında firmware/anahtar seçimi ve flash koruması kontrolleri devre dışıdır.

## Fuse okuma ve donanım kilidi programlama

Bootloader algılandığında GUI; bootloader sürümü ve derleme tarih/saatini, seri numarasını metin olarak (tümü `0xff` ise `Not provisioned`, geçersiz veya sonlandırılmamış string ise `Invalid serial format`), low/high/extended fuse baytlarını, ham lock baytını, uygulama ve boot yazma izinlerini ve ISP korumasını gösterir. **Read fuses / locks** bu değerleri yeniler ve LB2/LB1 seçicisini cihazdan okunan fiziksel modlara getirir. İlk durum yanıtı ve kilit programlamasından sonraki geri okuma da seçiciyi eşleştirir. Periyodik boşta durum paketleri kullanıcının henüz uygulamadığı seçimleri korur. Ayrılmış LB çifti için Keep current seçilir ve durum alanında ayrılmış olduğu belirtilmeye devam edilir; yenileme kilit yazma komutu göndermez. GUI hatalı BOOTRST/BOOTSZ ayarlarını, tam imaj CMAC'ını veya App metadata erişimini engelleyen okuma kilitlerini belirtir. Bağlantı kesildiğinde veya uygulamayı başlatma isteği gönderildiğinde durum temizlenir. Gelen baytlar yalnızca bootloader çerçeveleri olarak ayrıştırılır; uygulama metni yok sayılır ve mod tespitinde kullanılmaz.

**Apply lock…**, Fuses / locks sekmesinde yalnızca LB2/LB1 hedefini programlar. BLB0/BLB1 ve bütün fuse baytları salt okunur durum olarak gösterilir. Kalıcı kilit onayı seçilen LB modunu ve etkilerini açıklar. LB Mode 2 ISP flash/EEPROM programlamasını ve fuse yazımını; Mode 3 ayrıca ISP doğrulamasını ve boot-lock yazımını engeller. LB koruması tek başına bootloader uygulama güncellemelerini ve seri yazımını engellemez; mevcut BLB izinleri geçerlidir. Programlamadan sonra GUI, değişmemesi gereken BLB bitleri dahil altı fiziksel lock bitini beklenen durumla karşılaştırır ve geri okunan durumu gösterir. Kilit açma, firmware ve seri numarasını silen ISP chip erase gerektirir; bootloader/uygulamayı yeniden yükleyip seri numarasını tekrar kaydedin.

`CMD_INFO` (`0xb8`, boş istek) 46 bayt döndürür: 26 baytlık boot bilgisi, 16 baytlık seri numarası, ardından low fuse, high fuse, extended fuse ve lock baytları. Bootloader'a girişte ve boşta beklerken de gönderilir. `CMD_LOCK` (`0xb9`), yalnızca 1..0 bitlerini (`0x03`) içeren, tek baytlık ve sıfır olmayan programlama maskesini alır: maskede 1 olan bit, karşılık gelen LB bitini 0 yapar (LB2=1, LB1=0). Bütün BLB bitleri dahil diğer bitler ve sonuçta oluşacak ayrılmış LB2/LB1=`01` reddedilir. `0x01` maskesi Mode 1’den LB Mode 2’ye; `0x03` Mode 3’e; `0x02` ise Mode 2’den Mode 3’e geçiş içindir. Eski BLB maskeleri `0x04`, `0x10`, `0x14` reddedilir. Hiçbir maske fiziksel 0 bitini tekrar 1 yapamaz. Kilit ACK/NACK sıra numarası `0xfffe`; `NACK_LOCK` değeri 6'dır. Bootloader ACK öncesinde fiziksel bitleri tekrar okuyup doğrular, aktif aktarım veya FINISH bekleme süresinde kilitlemeyi reddeder ve ACK kaybından sonra tekrarlanan aynı kilit maskesini güvenle kabul eder. BEGIN, uygulama okuma veya yazma kilidi varsa reddedilir. Kilit/durum kontrol çerçeveleri kriptografik kimlik doğrulama yerine CRC kullanır; kilit isteği ISP kurtarmaya kadar güncellemeyi durdurabileceğinden seri servis erişimini sınırlandırın.

## Kilit grupları ve CLI kontrolü

GUI'de **Bootloader info** ve **Fuses / locks** ayrı sekmelerdir. Bootloader info yalnızca sürüm, derleme tarih/saati ve seri numarasını içerir. Kilit sekmesi fuse baytlarını, ham lock baytını ve her grubun fiziksel bitlerini, modunu ve izinlerini gösterir. Bit değeri `0` olduğunda bit programlanmıştır. BLB0/BLB1 Mode 1–4 gösterilir; GUI/CLI veya CMD_LOCK üzerinden yazılamaz, ISP üzerinden ayarlanır. Yalnızca LB2/LB1 hedef seçicisi vardır; Keep current ve Mode 1–3 sunar, ayrılmış `01` seçilemez. GUI ve CLI, 0 → 1 gerektiren bütün geçişleri reddeder; zaten uygulanmış modun seçilmesi işlem yapmaz. LB geçişleri 1 → 2 → 3 veya 1 → 3 şeklindedir. Mode 1 kilitli cihazı açmaz. Mevcut LB çifti ayrılmış `01` ise LB Mode 3, BLB bitlerini değiştirmeden düzeltebilir.

| Mod | Fiziksel bit çifti | BLB0: BLB02 / BLB01 | BLB1: BLB12 / BLB11 |
| --- | --- | --- | --- |
| 1 | `11` | App yazımı ve Boot → App okuması açık | Boot yazımı ve App → Boot okuması açık |
| 2 | `10` | App yazımı kapalı; Boot → App okuması açık | Boot/seri yazımı kapalı; App → Boot okuması açık |
| 3 | `00` | App yazımı ve Boot → App okuması kapalı | Boot/seri yazımı ve App → Boot okuması kapalı |
| 4 | `01` | Boot → App okuması kapalı; App yazımı açık | App → Boot okuması kapalı; Boot yazımı açık |

| LB modu | LB2 / LB1 | ISP etkisi |
| --- | --- | --- |
| 1 | `11` | Programlama ve doğrulama açık |
| 2 | `10` | Programlama kapalı |
| 3 | `00` | Programlama ve doğrulama kapalı |
| Ayrılmış | `01` | Kullanılmamalı |

LB koruması harici programlama/doğrulamayı kontrol eder; tek başına bootloader SPM güncellemelerini **engellemez**. Bu uygulama yazımlarını BLB0 kontrol eder. Boot alanı/seri yazımını BLB1 kontrol eder. Okuma kilidi modları, [ATmega328P veri sayfası](https://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-7810-Automotive-Microcontrollers-ATmega328P_Datasheet.pdf), tablo 26-2, 26-3 ve 27-2'de açıklandığı gibi kesmeleri de etkiler. ATmega328P, LB2/LB1 bitlerini SPM ile programlamayı destekler (veri sayfası bölüm 26.8.7); bu protokol yalnızca bu iki biti kullanıma açar. BLB ve fuse yazımı ISP gerektirir. Donanım korumasını açmak chip erase gerektirir. Yalnızca LB maskesine izin veren politikayı cihazda uygulamak için uyumlu bootloader’ı ISP ile yükleyin; önceden yüklenmiş bootloader değiştirilene kadar kendi komut politikasını korur.

Flasher argümansız çalıştırıldığında GUI açılır. Komut verildiğinde **Qt yüklenmeden** CLI çalışır. Python ortamınız aktifken örnekler:

```sh
python Tools/Flasher/main.py ports
python Tools/Flasher/main.py verify --file App/Release/App_encrypted.bin --key .local/signing_public.pem
python Tools/Flasher/main.py info --port COM5
python Tools/Flasher/main.py bootloader --port COM5
python Tools/Flasher/main.py flash --port COM5 --file App/Release/App_encrypted.bin --key .local/signing_public.pem
python Tools/Flasher/main.py application --port COM5
```

Linux'ta `COM5` yerine `/dev/ttyUSB0` kullanın. Windows'ta komutları `.\.venv-win\Scripts\python.exe` ile çalıştırın. Eşdeğer modül girişi `python -m Tools.Flasher.cli` şeklindedir. `info`, `bootloader`, `flash` ve `lock`, önce 0,5 saniye bootloader paketlerini dinler. Header gelmezse bir kez `BOOT\n` gönderip HEADER/INFO ile girişi doğrular; uygulama mesajı gerekmez. Genel amaçlı uygulama bu giriş komutunu desteklemeli veya cihaz haricen bootloader moduna alınmalıdır. `application`, RESET gönderir ve seri yazım başarılı olur olmaz cihaz çıktısını beklemeden döner. JSON sonucu `application_start: requested`, `confirmed: false` ve `mode: unknown` bildirir. Komutun gönderilmiş olması uygulamanın gerçekten başladığını kanıtlamaz; bootloader çalıştırmadan önce imaj CMAC kontrolünü sürdürür. CLI komutlarından önce GUI'nin port bağlantısını kapatın.

`verify` çevrimdışı çalışır. `flash`, Ed25519 imzasını **seri portu açmadan önce** doğrular; donanım kimliğini, güncel uygulama okuma/yazma izinlerini ve aynı/yeni sürüm kuralını kontrol eder; ardından BEGIN, sıralı şifreli sayfalar ve FINISH gönderir. `--force` yalnızca sürüm kuralını aşar. Paketler en fazla beş kez denenir; eski/tekrarlanan ACK aktarımı ilerletemez, authentication/image/lock NACK aktarımı durdurur. `--timeout SECONDS` cevap süresini belirler (varsayılan 2); FINISH için en az 8 saniye tanınır. GUI ve CLI paket/sürüm/kilit politikasını paylaşır. FINISH ACK, firmware'in doğrulandığını bildirir; uygulama bootloader'ın bekleme süresinden sonra başlar ve bu ACK ile henüz çalıştığı doğrulanmaz.

CLI kilit programlaması `--lb-mode 1|2|3` ve `--yes` ile açık onay gerektirir. Aşağıdaki komut, BLB0 uygulama okuma/yazmasına izin verdiği sürece bootloader güncellemelerini koruyarak ISP programlama/doğrulamasını engelleyen LB Mode 3 uygular:

```sh
python Tools/Flasher/main.py lock --port COM5 --lb-mode 3 --yes
```

ISP doğrulamasını koruyarak programlamayı kapatmak için `--lb-mode 2`; ikisini kapatmak için `--lb-mode 3` kullanın. BLB yazma seçenekleri kabul edilmez. Mode 1 yalnızca LB zaten açıksa kabul edilir. Araç LB etkilerini stderr’e yazar; bitlerin açılmasını gerektiren bütün geçişleri CMD_LOCK göndermeden reddeder, BLB0/BLB1 bitlerini korur ve programlamadan sonra altı biti doğrular. Başarılı komutlar stdout’a JSON; flash ilerlemesi ve hatalar stderr’e yazılır. Çıkış kodları başarı için 0, çalışma/doğrulama hatası için 1, geçersiz argüman için 2’dir. CLI info seri numarasını dolgusuz metin olarak döndürür; `serial_valid`, geçerli metin olup olmadığını bildirir. Silinmiş veya geçersiz alanlarda `serial: null` döner; eski ikili seri numaraları `--replace` ile değiştirilebilir. Seri numarası yazımı ayrı `Tools/write_serial.py` aracında kalır.

## Araçların CLI kullanım referansı

Örnekleri Python ortamı aktifken proje kökünden çalıştırın; Linux’ta `COM5` yerine `/dev/ttyUSB0`, Windows PowerShell’de `.\.venv-win\Scripts\python.exe` kullanın. Aşağıdaki komutlar bağımsız kullanım örnekleridir; ihtiyacınız olan işlemi seçin. Başka araç aynı portu açmadan önce GUI bağlantısını kapatın. `.local` yolları geliştirme örnekleridir; üretim anahtarlarını depo dışında tutun.

| Araç | Argümanlar ve davranış |
| --- | --- |
| `Tools/ensure_keys.py` | `DIRECTORY`; eksik geliştirme cihaz/imzalama anahtarlarını oluşturur; imzalama anahtarı oluşturulurken public key yazılır. Mevcut private key korunur. `make all` normalde otomatik çağırır. |
| `Tools/key_header.py` | `KEY_HEX OUTPUT_HEADER`; bootloader derlemesinin kullandığı özel C anahtar tanımını üretir. Çıktıyı Git tarafından yok sayılan derleme dizininde tutun. Make/Studio normalde bu adımı çalıştırır. |
| `Tools/encrypt_image.py` | `-f APP_HEX --device-key KEY_HEX --signing-key PRIVATE_PEM [-o PACKAGE_BIN]`; uygulamayı imzalar/şifreler. Varsayılan çıktı `<input-stem>_encrypted.bin`; derlenmiş App HEX gerektirir. |
| `Tools/decrypt_image.py` | `-f PACKAGE_BIN --device-key KEY_HEX --verify-key PUBLIC_PEM [-o PLAIN_BIN]`; yalnızca test için imza/CMAC doğrulaması ve çözme yapar. Varsayılan çıktı `<package-stem>.plain.bin`. Üretim flash akışında kullanmayın. |
| `Tools/Flasher/main.py` | Argümansız: GUI. Komutlar: `ports`, `verify`, `info`, `bootloader`, `application`, `flash`, `lock`. `verify` için `--file`, isteğe bağlı `--key`; port komutları için `--port`, isteğe bağlı `--timeout` (varsayılan 2 saniye) gerekir. `flash` ayrıca `--file`, isteğe bağlı `--key` ve `--force` (yalnızca sürüm kuralı) kullanır. `lock`, `--lb-mode {1,2,3} --yes` gerektirir. |
| `Tools/write_serial.py` | `--port PORT --serial TEXT [--replace] [--timeout SECONDS]`; ayrı seri kaydetme aracı, 1..15 yazdırılabilir UTF-8 baytı, otomatik NUL/dolgu, varsayılan timeout 2 saniye. `--replace` mevcut serinin değiştirilmesine açıkça izin verir. |

```sh
python Tools/ensure_keys.py .local
python Tools/key_header.py .local/device_key.hex Bootloader/Release/device_key.h
python Tools/encrypt_image.py -f App/Release/App.hex --device-key .local/device_key.hex --signing-key .local/signing_private.pem -o App/Release/App_encrypted.bin
python Tools/decrypt_image.py -f App/Release/App_encrypted.bin --device-key .local/device_key.hex --verify-key .local/signing_public.pem -o .local/App_verified.bin
python Tools/Flasher/main.py
python Tools/Flasher/main.py ports
python Tools/Flasher/main.py verify --file App/Release/App_encrypted.bin --key .local/signing_public.pem
python Tools/Flasher/main.py info --port COM5 --timeout 2
python Tools/Flasher/main.py bootloader --port COM5
python Tools/Flasher/main.py application --port COM5
python Tools/Flasher/main.py flash --port COM5 --file App/Release/App_encrypted.bin --key .local/signing_public.pem --timeout 2
python Tools/Flasher/main.py lock --port COM5 --lb-mode 3 --yes
python Tools/write_serial.py --port COM5 --serial "DEVICE-001" --timeout 2
python Tools/write_serial.py --port COM5 --serial "DEVICE-002" --replace --timeout 2
```

Komut yardımı için `python Tools/Flasher/main.py --help` veya `python Tools/Flasher/main.py COMMAND --help` kullanın; her bağımsız araç da `--help` destekler. Başsız flasher’ın eşdeğer girişleri `python Tools/Flasher/cli.py COMMAND ...` ve `python -m Tools.Flasher.cli COMMAND ...` şeklindedir. `image_format.py`, `policy.py`, `protocol.py` ve üretilen `Flasher_GUI.py` kütüphane/UI destek dosyalarıdır; bağımsız CLI içermez. Flasher stdout’a JSON, stderr’e hata/ilerleme yazar (çıkış: başarı 0, çalışma hatası 1, argüman hatası 2). Seri yazıcı başarıda `Serial verified: TEXT` döndürür (çıkış 0), hataları stderr’e yazar (çıkış 1; geçersiz argüman 2). `--force` kimlik doğrulama, donanım kimliği veya fiziksel kilitleri aşamaz.

## Güvenlik ve güç kesintisi sınırları

Eski revizyonlarda AES anahtarı ve RSA private key Git tarafından takip edilmişti. Bu anahtarlar Git geçmişinden erişilebilir ve üretimde kullanılmamalıdır. Yeni üretim anahtarları oluşturup cihazları yeniden provision edin. Güncel `AVR3` header/paketi `AVR2` ve daha eski bootloader ile uyumlu değildir; geçiş ISP programlayıcı gerektirir. Bootloader içindeki AES anahtarını okumaya karşı doğru fuse ve lock bitlerini yapılandırın.

ATmega328P'de ikinci uygulama bankası yoktur. Doğrulanmamış sayfa flash'a yazılmaz; fakat geçerli güncelleme başladıktan sonra güç kesilirse eski uygulama kısmen silinmiş olabilir. Bootloader geçersiz imajı başlatmaz ve yeni güncelleme bekler. Fiziksel erişim, signing private key'in veya cihaz AES anahtarının ele geçirilmesi bu tasarımın güvenlik sınırları dışındadır.
