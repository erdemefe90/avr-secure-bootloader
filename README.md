
# AVR Secure Bootloader

This repository contains a secure bootloader for Atmel AVR microcontrollers along with
an example application and Python‑based support tools. Before starting the
application, the bootloader checks the signature and integrity of the encrypted
firmware image so that only authorised software can run and the device cannot be
compromised by fake or corrupted files.

## Features

* 🔒 **Encryption:** The firmware image is encrypted twice using a fixed
  AES‑128 key and an RSA‑2048 key pair; only someone with the private key can
  decrypt the file.
* 🧪 **Integrity:** CRC16‑CCITT is calculated for every packet and for the
  entire image. Packets with wrong CRC or length are rejected with a `NACK`.
* 🔌 **Serial update:** The bootloader operates over RS485/USART and talks to
  a PyQt‑based flasher application.
* ✅ **Image check:** The bootloader checks the `BOOT_MAGIC` and CRC fields and
  jumps straight to the application if the image is valid.
* 🔁 **Shared memory:** A `shared_memory_t` structure shares the boot command and
  baud rate between the bootloader and the application.
* 📦 **Modular directories:** The code is organised into separate `Bootloader`,
  `App`, `Common` and `Tools` folders.

## 🎯 Project goal

The aim of this project is to produce a unique firmware image for each
customer. Only the holder of the RSA private key can decrypt the image. Because
`encrypt_image.py` uses a random AES‑256 key and IV, every build is unique even
for the same customer.

## Directory structure

| Directory                 | Description                                                                                                              |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `Bootloader/`            | Bootloader code, UART and CRC drivers, the AES library (`tiny‑AES‑c` submodule) and a custom linker script.              |
| `App/`                   | Example application that places an `image_header_t` in the correct section and jumps to the bootloader when it receives
|                          | the command `BOOT\n`.                                                                                                    |
| `Common/`                | Shared definitions (`image.h`, `crc.h`, `uart.h` etc.) and data structures used by both the bootloader and the app.       |
| `Tools/`                 | Python scripts for encrypting, decrypting and flashing firmware images via the serial port, plus a PyQt5 GUI.            |
| `Bootloader/tiny‑AES‑c/` | A tiny C implementation of the AES algorithm used by the bootloader in CBC mode.                                          |

## Bootloader operation

The bootloader resides in the upper flash addresses (for example the `.text`
section starts at 0x7000). On reset the `boot_main.c` function runs and executes
these steps:

1. **Hardware initialisation:** Interrupt vectors are relocated to the boot area.
   The watchdog timer, LED, RS485 direction pins, a 1 ms timer and the UART are
   set up. The `shared_area.boot_key` is cleared.
2. **Application validation:** The bootloader reads the `BOOT_MAGIC` and image
   CRC values from flash. If the image is valid and `boot_key` is not set, it
   jumps directly to the application.
3. **Update mode:** If validation fails or `boot_key` is set, the bootloader
   waits on the serial port for an update. It sends a `BOOT_CMD_HEADER`
   containing the image header every 250 ms until a response is received.
4. **Handshake:** The host sends a `BOOT_CMD_INFO` packet. The bootloader takes
   the 16‑byte IV from this packet, initialises the AES context and replies
   with an ACK.
5. **Data transfer:** The host sends `BOOT_CMD_FLASH` packets containing the
   length, target offset and AES‑CBC encrypted data. The bootloader decrypts
   the payload, writes it to flash and responds with an ACK for correct
   packets or a NACK for incorrect packets.
6. **Completion:** When the last block is received, the bootloader calculates
   the CRC of the new image and compares it with the header value. If they
   match it jumps to the application; otherwise it resets.
7. **Reset:** The host can send `BOOT_CMD_RESET` at any time to reboot the
   device.

### 📡 Protocol format

Every bootloader command starts with a start‑of‑text marker (`STX`), followed
by the command code and a length byte. The payload follows and finally the
16‑bit CRC. The packet format can be summarised as:

```
| STX (0xAA) | CMD | LEN | DATA[n] | CRC_L | CRC_H |
```

* **STX (Start of Text):** Constant 0xAA at the start of every packet.
* **CMD:** Command code (see table below). Values range from 0xB0 to 0xB7.
* **LEN:** Length of the `DATA` field in bytes.
* **DATA:** Variable‑length data depending on the command (encrypted payload,
  offset, IV, etc.).
* **CRC_L/CRC_H:** Low and high bytes of the CRC16‑CCITT result.

Main command codes:

| Command           | Code   | Description                                                         |
|-------------------|--------|---------------------------------------------------------------------|
| `BOOT_CMD_HEADER` | `0xB0` | Bootloader sends the current image header.                          |
| `BOOT_CMD_INFO`   | `0xB1` | Host sends IV; bootloader responds with ACK and sets up AES.       |
| `BOOT_CMD_FLASH`  | `0xB3` | Encrypted data block and offset; bootloader decrypts and writes.    |
| `BOOT_CMD_ACK`    | `0xB5` | Acknowledgement for a valid packet.                                 |
| `BOOT_CMD_NACK`   | `0xB6` | Negative acknowledgement if length or CRC is wrong.                 |
| `BOOT_CMD_RESET`  | `0xB7` | Reset the bootloader or MCU.                                        |

### Image header (`image_header_t`)

Both the bootloader and the application share the same structure to hold image
metadata. It is defined in `Common/image.h` and placed in the `.image_header`
section. Fields:

* `magic` (32‑bit): A constant (`0xEFEFEFEF`) indicating that the image is valid.
* `sw_version`: Software version (major, minor, revision, build).
* `hw_version`: Hardware version (major, minor, revision).
* `compile_date` and `compile_time`: Build date and time (`__DATE__` / `__TIME__`).
* `avr_gcc_version`: AVR‑GCC version used to build the image (`__VERSION__`).
* `reserved`: Reserved for future use.
* `image_size`: Size of the application in flash (read by the bootloader).
* `crc`: CRC16 of the application image. The bootloader verifies this after
  flashing. The field in the header is reserved for future use; integrity is
  verified using the two CRC bytes appended to the end of the image.

## 🗺️ Flash map

The linker scripts (`Bootloader/Bootloader_Custom.ld` and `App/App_Custom.ld`)
define the memory layout. Key points:

* **Application (0x0000–0x6FFF):** The application’s `.text` starts at the
  beginning of flash. At address 0x0000 is the interrupt vector table; the
  `.image_header` (88 bytes) is placed right after the vectors. The remaining
  space is used for application code.
* **Bootloader (0x7000–0x7FFF):** The bootloader’s `.text` section starts at
  0x7000 via the `-section-start=.text=0x7000` linker option so that the
  application cannot overwrite it.
* **Shared memory and .data (0x800000+):** `Bootloader_Custom.ld` places an
  eight‑byte `.shared_memory` section at 0x800100 and `.data` starts at
  0x800108. Both the application and the bootloader access this area.
* **CRC:** `encrypt_image.py` appends a two‑byte CRC to the end of the image.
  The `crc` field in `image_header_t` is reserved for later use; integrity is
  checked using the two trailing bytes.

## Encryption scheme

Two‑level encryption is used to protect the firmware during updates, handled
automatically by `Tools/encrypt_image.py`:

1. Read the compiled HEX file, update the `image_size` field and calculate the
   image CRC, appending it to the end of the data.
2. Pad the data to 16‑byte blocks using PKCS#7.
3. Encrypt the data with a fixed AES‑128 key and a randomly generated IV in
   AES‑CBC mode.
4. Create a “secure block” containing the header and IV and encrypt it again
   with a random AES‑256 key.
5. Encrypt this AES‑256 key and IV with the user‑supplied RSA‑2048 public key.
6. The final file contains the RSA‑encrypted key/IV, the AES‑256‑encrypted
   block and a SHA‑256 digest. The flasher uses the private key to reverse
   these steps; `decrypt_image.py` is only for testing.

The fixed AES key is defined in the bootloader (`Bootloader/bootloader.c`)
as `aes_key` and appears in `encrypt_image.py` in hexadecimal. You can replace
this key if your security requirements demand it.

## Example application

The example in `App/` demonstrates normal operation:

* An `image_header_t` instance is placed in the `.image_header` section and
  contains version and build information.
* The `main` function toggles an LED and sends “Hello World!!\r\n” every
  250 ms.
* When “BOOT\n” is received over UART, it writes `BOOT_KEY` into
  `shared_area.boot_key` and triggers a short watchdog reset to enter the
  bootloader.

The application’s Makefile automatically calls the Python script after
building to encrypt `app_main.hex` and produce an `_encrypted.bin` file, ready
for the flasher.

## Tools

### `encrypt_image.py`

Encrypts a compiled `.hex` file into a `.bin` suitable for the bootloader. For
example:

```
python Tools/encrypt_image.py -f App/app_main.hex -k public.pem
```

Here `public.pem` is your 2048‑bit RSA public key; the output is
`App/app_main_encrypted.bin`.

### `decrypt_image.py`

Opens an encrypted `.bin` with an RSA private key, extracts the secure block
and shows the image contents as a hexdump. Because the flasher performs this
automatically via `image_extract.py`, this script is intended for testing only.

### Flasher (PyQt5 GUI)

`Tools/Flasher/main.py` is a graphical interface written with PyQt5. With it
you can:

* Connect to a serial port and choose the baud rate.
* Use the **Boot Mode** button to send `BOOT\n` and enter the bootloader;
  use the **Reset** button to restart the device.
* Select an encrypted `.bin` and RSA private key to decrypt the header,
  view version/size/date/CRC information and load the firmware via the
  **Flash** button.
* Monitor progress and status messages during the update.

You can also flash via the command‑line scripts. The flasher depends on
`pyserial` and `PyQt5`.

## Building and usage

You can build this project in two ways: either open the `.cproj` files in
Microchip Studio on Windows or run `make` with avr‑gcc in each directory. In
both cases you need AVR‑GCC/avr‑libc installed, Python 3 with `intelhex`,
`cryptography`, `pyserial` and `PyQt5` packages, and OpenSSL to generate keys.

### Compiling the bootloader (avr‑gcc)

```
cd Bootloader
make
```

The Makefile defines the target MCU, clock frequency and linker addresses.
The `.text` section starts at 0x7000; the resulting `bootloader.hex` can be
programmed into the device with your favourite programmer.

#### Fuse settings

To ensure the MCU starts in the bootloader after reset, configure the fuses
appropriately. For example, on an ATmega328P set **BOOTRST=0** (start from the
boot area) and **BOOTSZ=00** (reserve a 4 KB boot section at 0x7000). You can
set these fuses via Microchip Studio or with `avrdude`.

### Compiling and encrypting the example application

```
cd App
make
```

The Makefile invokes `encrypt_image.py` after the build to create
`_encrypted.bin`, which the flasher can load directly.

### Generating RSA keys

A pair of RSA keys is required to load encrypted firmware. For example:

```
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private.pem -out public.pem
```

Use `private.pem` with the flasher and `decrypt_image.py`; provide
`public.pem` to `encrypt_image.py`. Keep your private key in a safe place.

### Using the flasher

1. While the normal application is running, send `BOOT\n` to switch to boot
   mode.
2. Run `python Tools/Flasher/main.py`, select the correct serial port and
   baud rate.
3. Click **Connect** and then **Boot Mode**; the bootloader will start
   sending header packets.
4. Choose your encrypted `.bin` file and the RSA private key; the flasher
   will display the header information.
5. Click **Flash** to start the update; when finished the device will run
   the new application.

## Customisation

* **AES key:** The default 16‑byte key is defined in `bootloader.c` and
  `encrypt_image.py`. If you want to use your own key, update both files
  consistently.
* **Boot command and key:** Modify the `BOOT_COMMAND` and `BOOT_KEY` constants
  in `Common/image.h` to customise the mechanism for switching between the
  application and the bootloader.
* **Memory addresses:** The bootloader and application address ranges are set in
  the Makefiles; adjust them for different MCU types or bootloader sizes.
* **Serial communication:** UART and RS485 parameters are defined in `uart.h`
  and `boot_main.c`. You can select a different baud rate using
  `shared_area.baud_rate` and by modifying the Makefile.

## 🛡️ Security notes

All keys in this project are examples. For a secure product:

* Generate a unique RSA key pair for each customer and keep the private key
  secret.
* Replace the hard‑coded AES‑128 key in the bootloader and the `AES_KEY`
  constant in the script with your own values.
* Use different keys for different customers so that images cannot be
  substituted between devices.
* You are responsible for any security issues that arise while using this
  project.

## 📌 TODO

Planned improvements for this repository:

* Optimise the bootloader to reduce its flash usage and free space for new
  features.
* The `baud_rate` field in `shared_area` is currently unused; it should either
  be used to exchange the baud rate between the app and bootloader or removed.
* Add error codes to `NACK` packets for better error handling.
* Rewrite the flasher to improve code quality.
* Add timeout checks to handle lock‑up situations automatically.

## Contribution and licence

This project is released under the MIT Licence; see the `LICENSE` file for
details. Contributions and pull requests are welcome. The project is for
educational purposes; for commercial use you should perform your own security
analysis.