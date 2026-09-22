---
trigger: always_on
---

- Bana sadece türkçe cevap ver.
- projenin en büyük handikapı 4kb'lık bootloader alanının sınırları.
- Güvenlik için ilk güvenilen şey sadece encrypt_image.py dosyası ve bootloader C kodunda ortak kullanılan AES128-CBC key olacak.
- encrypt_image.py ve flasher.py iki ayrı uygulama olacak.
- integrity için AES128-CBC kullanılacak.(başka bir aes modülü kullanmak kod size çok artırıyor)
- bootloder girişi için App "BOOT\n" aldığında shared memory alanına bir key yazacak ve reset atacak. Resetten sonra bootloader bu keye bakıp key yazılırsa bootloaderdan değilse imagedan başlayacak.
- bootloader RS485 desteklemek zorunda.
- image_header_t yapısındaki gereksiz alanlar(uint8_t reserved[39]) uygun bir şekilde (aligment) kısaltılacak. Buna göre linker scriptler güncellenebilir.
- flasher uygulaması integrity check yapacak. Yannlış yapılandırılmış RSA AES256 ve SHA256'dan vazgeçilecek. eliptic curve kullanabilir. encrypt_image.py tarafından şifrelen imaj 2. kez şifrelenerek bu şifreyi flasher çözebilir. veya başka güvenl bir yöntem.
- boorloader ilk çalıştığında periyodik olarak app alanındaki image_header_t verisini gönderecek. Flasher bunu aldığında IV dönerek flash blobları almaya hazır olduğunu bildirecek.
- flasher uygulamasında force checkboxı olacak. eğer mcu'daki image ile seçilen image versiyonu aynı ise veya seçilen daha düşük versiyonda flashlama başlamayacak. ancak force seçilirse bir warning popup ile flashlama başlayacak.
- bootloader app'e atlamadan önce inregrity check yapacak eğer image yoksa veya check fail ise bootloader modunda kalmaya devam edecek yeni image bekleyecek. integrity check pass olursa app'e atlayacak.
- Flasher uygulaması thread ile çalışacak. gui flashlama esnasında kitlenmeyecek.
- flasher - bootloader arasındaki işlemler ACK NACK ve timeout ile yapılacak işlem bir yerde kesilmeyecek.
- README.md güncel tut.
- mevcut bootloader projesinde size düşürme amaçjlı iterasyonlar yapabilirsin.