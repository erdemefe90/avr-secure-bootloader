# AVR Secure Bootloader

Bu proje, ATmega328P mikrodenetleyicileri için tasarlanmış, 4KB limitlerine optimize edilmiş ve güvenlik standartları yükseltilmiş bir Secure Bootloader sistemidir.

## Temel Özellikler

*   **Boyut Optimizasyonu:** Bootloader kodu 4KB (4096 byte) sınırına sığacak şekilde agresif bir şekilde optimize edilmiştir (~3.5KB).
*   **AES-CTR Şifreleme:** İmaj verileri AES-128 CTR modu kullanılarak şifrelenir. Bu mod, sadece şifreleme (encryption) fonksiyonlarını kullanarak deşifreleme yapabildiği için Flash alanından tasarruf sağlar.
*   **CBC-MAC Bütünlük Kontrolü:** İmaj bütünlüğü AES-CBC son bloğu (Message Authentication Code) kullanılarak doğrulanır.
*   **Nonce Mekanizması:** Replay saldırılarını önlemek için her flaşlama oturumunda bootloader tarafından üretilen rastgele bir "Nonce" kullanılır.
*   **RS485 Desteği:** UART katmanı RS485 transceiver kontrolü için otomatik yönlendirme (DE/RE pin kontrolü) özelliğine sahiptir.
*   **Threaded Flasher GUI:** Python tabanlı Flasher uygulaması, flaşlama sırasında arayüzün donmasını engelleyen threading yapısına sahiptir.
*   **Güvenli Geçiş:** Uygulama (App) içerisinden `BOOT\n` komutu ile shared memory üzerinden güvenli bootloader geçişi sağlanır.

## Sistem Mimarisi

### İmaj Formatı
Şifrelenmiş imaj dosyası (`.bin`) şu yapıdadır:
1.  **Encrypted Payload:** AES-CTR ile şifrelenmiş uygulama kodu.
2.  **Image Header (56 byte):** Sürüm bilgileri, boyut ve derleme zamanı (Plaintext).
3.  **IV (16 byte):** CTR modu için rastgele üretilmiş Initialization Vector.
4.  **CBC-MAC (16 byte):** Padded plaintext üzerinden hesaplanmış bütünlük imzası.

### Bootloader Protokolü
1.  **Handshake:** Bootloader açılışta Header bilgisini periyodik olarak yayınlar.
2.  **Authentication:** Flasher `BOOT_CMD_INFO` ile IV gönderir, Bootloader buna rastgele bir `Nonce` ile cevap verir.
3.  **Data Transfer:** Veriler 128 byte'lık bloklar halinde ACK/NACK mekanizması ile gönderilir.
4.  **Verification:** Son blok yazıldıktan sonra Bootloader imajın bütünlüğünü (CBC-MAC) kontrol eder ve geçerliyse uygulamaya atlar.

## Kurulum ve Kullanım

### Bağımlılıklar
*   avr-gcc
*   Python 3.10+
*   `pip install -r Tools/requirements.txt --break-system-packages`

### Derleme
```bash
# Tüm projeyi derlemek için
make -C App all
make -C Bootloader all
```

### Flaşlama
`Tools/Flasher/main.py` dosyasını çalıştırarak GUI üzerinden `.bin` dosyasını seçip flaşlama işlemini başlatabilirsiniz.

## Güvenlik Notları
*   `AES_KEY` hem Bootloader C kodunda hem de Python araçlarında ortak olarak tanımlıdır. Üretim aşamasında bu anahtarın değiştirilmesi KRİTİKTİR.
*   "Force" seçeneği, versiyon kontrolünü atlayarak aynı veya daha düşük sürümlerin yüklenmesine izin verir.
*   "Lock Bits" seçeneği ile flaşlama sonrası MCU kilit bitleri programlanabilir.