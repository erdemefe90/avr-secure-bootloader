# AVR Secure Bootloader

Turkish documentation: [README-TR.md](README-TR.md)

Contributor and coding-agent guide: [AGENTS.md](AGENTS.md)

This repository contains a 4 KB bootloader for the ATmega328P, a sample application, and a PyQt5 flasher that communicates over RS485. When the sample application receives `BOOT\n`, it writes `0xabcd` to the 16-bit `boot_key` in `.shared_memory` and enters the bootloader through a watchdog reset. Both programs use a fixed **115200 baud** rate. The shared RAM area has no baud-rate field.

## Setup and build

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
make all
make test
```

You can also run `make app`, `make bootloader`, or `make package` separately. The root Makefile includes the App and Bootloader Makefiles. `make all` creates `App/Release/App.hex`, `Bootloader/Release/Bootloader.hex`, and the signed `App/Release/App_encrypted.bin` package.

The first build generates random **development** keys under `.local/`. Git ignores this directory. For production, keep keys outside the repository and pass their paths explicitly:

```sh
make clean
make all DEVICE_KEY_FILE=/secure/device_key.hex SIGNING_KEY_FILE=/secure/signing_private.pem
AVR_TRUSTED_PUBLIC_KEY=/secure/signing_public.pem python Tools/Flasher/main.py
```

`device_key.hex` contains exactly 32 hexadecimal digits representing a 16-byte key. The signing key is an Ed25519 private key in PEM format. Distribute the corresponding verification public key with the trusted flasher installation; never take it from a firmware package. The default `.local/signing_public.pem` is for development only. The flasher's **Trusted key / Browse** control accepts an Ed25519 public-key PEM for development, key rotation, and service workflows. Selecting another key immediately revalidates the selected firmware and disables flashing if verification fails. In a controlled production setup, start the flasher with `AVR_TRUSTED_PUBLIC_KEY` and restrict which public keys operators may select. `Tools/decrypt_image.py` verifies and decrypts a package for testing; it is not part of the production flashing flow.

Example commands for generating production keys in a secure environment:

```sh
openssl rand -hex 16 > /secure/device_key.hex
openssl genpkey -algorithm ED25519 -out /secure/signing_private.pem
openssl pkey -in /secure/signing_private.pem -pubout -out /secure/signing_public.pem
chmod 600 /secure/device_key.hex /secure/signing_private.pem
```

The App and Bootloader projects in `AVR_Bootloader.atsln` can also be built with Microchip Studio. They use the same linker scripts. Python 3 and the packages from `requirements.txt` must be available in Studio's build environment. The Bootloader pre-build step generates `device_key.h` from the local development key. For production, update that step and the App packaging step to use your secure key paths.

## Memory layout

| Region | Address | Constraint |
| --- | --- | --- |
| Application flash | `0x0000–0x6fff` | 28 KB; 128-byte pages |
| Image header | `0x0100–0x0143` | 68 bytes; starts at a page boundary |
| Bootloader flash | `0x7000–0x7fff` | At most 4096 bytes of `.text` plus initialized `.data` |
| Shared SRAM | `0x800100–0x800101` | `.shared_memory`; only `boot_key` |
| Normal SRAM | `0x800102` onward | `.data`, `.bss`, and stack |

The linker scripts use `ASSERT` to check the actual header and shared-object sizes, their addresses, SRAM bounds, and the bootloader flash limit. The packager pads the application image to a full page with `0xff`; `image_size` records the padded length. The bootloader checks the image size, hardware ID, and page alignment.

The image header has no separate schema-version field. Package format selection is handled only by the clear-text `AVR2` package magic. The bootloader and tools intentionally reject the legacy header and package layouts; backward compatibility with pre-modernization images is not supported.

The packed 68-byte header contains `magic`, `hw_id`, the three software-version bytes, `build_num`, `image_size`, the 12-byte compile date, 9-byte compile time, 6-byte AVR-GCC version, 12-byte AES-CTR nonce, and 16-byte full-image CMAC tag, in that order. The GUI displays the build metadata from both the selected signed package and the detected device.

`Common/image.h` is the complete shared C interface between the application and bootloader. It contains only `image_header_t`, `shared_area_t`, and `BOOT_KEY`. Flash-map, protocol, CRC, and application command definitions live in the project that owns them.

Set the ATmega328P fuses to **BOOTRST programmed** and **BOOTSZ1:0 = 00** so that the 4 KB boot section starts at `0x7000`. For production, configure the general lock bits to restrict external reads and the boot lock bits to prevent the application from reading or writing boot code, following the device datasheet. The bootloader must retain permission to write the application section. The flasher GUI does not set fuses or lock bits.

## Package and verification

`Tools/encrypt_image.py` writes the image size, a random 96-bit nonce, and a full-image AES-CMAC tag into the header from the application HEX file. It derives separate encryption and MAC keys from the embedded AES-128 device key. The image is encrypted with AES-CTR. Each encrypted page also carries an AES-CMAC tag over the header, page index, and ciphertext.

The package contains a clear-text copy of the header so that the flasher can display its version. An Ed25519 signature covers the header, every encrypted page and tag, and the package length. The flasher rejects packages whose signatures do not verify. The AVR does not perform Ed25519 operations: it checks each page's CMAC with its own key **before writing flash**. It also checks the full image's CMAC before starting the application. CRC16 detects transmission errors in RS485 frames; it is not an authenticity check.

The package layout, AES counter encoding, and commands are defined in `Tools/image_format.py`, `Tools/Flasher/protocol.py`, and `Bootloader/protocol.h`. The bootloader ACKs a repeated page without writing it again. It also briefly accepts a repeated `FINISH` request if its ACK was lost. NACK reason codes distinguish packet, state, size, authentication, and image errors. RS485 transmission direction returns to receive mode after the final transmitted bit.

## Flasher

```sh
source .venv/bin/activate
python Tools/Flasher/main.py
```

On Windows, create and use a separate Windows virtual environment:

```powershell
py -3 -m venv .venv-win
.\.venv-win\Scripts\python.exe -m pip install -r requirements.txt
.\.venv-win\Scripts\python.exe Tools\Flasher\main.py
```

The application handles PyQt5's platform-plugin path explicitly on Windows, including project paths that contain non-ASCII characters.

Connect to the serial port. If the application is running, click **Go Bootloader** to send `BOOT\n`. The GUI confirms the transition when it receives a bootloader header. **Go Application** is available only while the bootloader is detected. It sends the reset command and confirms the transition when the sample application emits its periodic `Hello World!!` message. If the expected response does not arrive, the GUI reports a timeout. The serial speed is fixed at 115200 baud.

Use **Trusted key / Browse** to select the Ed25519 public key that is allowed to verify firmware packages. Select a signed `.bin` package and click **Flash**. After signature verification, the GUI displays the version, hardware ID, compile date/time, AVR-GCC version, and size from the package header. By default, it disables Flash for an image with the same or an older version than the detected device image. **Force** overrides only this GUI version rule; it does not bypass signature, hardware ID, or AVR CMAC checks. The GUI rule is not a device-enforced anti-rollback mechanism.

## Security and power-loss limits

Earlier revisions tracked an AES key and an RSA private key. They remain accessible in Git history and must never be used in production. Generate new production keys and provision devices again. The new package format and key are incompatible with the old bootloader, so the first migration requires an ISP programmer. Configure the appropriate fuse and lock bits to protect the bootloader's embedded AES key from readout.

The ATmega328P has no second application bank. Unauthenticated pages are rejected before writing, but a power loss after a valid update begins can leave the previous application partly erased. The bootloader will not start an invalid image and remains available for another update. Physical access and compromise of either the signing private key or the device AES key are outside the guarantees of this design.
