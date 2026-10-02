# AGENTS.md

This file is the working guide for coding agents and maintainers. Read it before changing the repository. The public project overview remains in `README.md` and `README-TR.md`.

## Repository and Git workflow

- The shared Windows/WSL checkout is `C:\Projects\avr-secure-bootloader`, mounted in WSL as `/mnt/c/Projects/avr-secure-bootloader`.
- Do not work from an old copy under `~/Desktop/avr-secure-bootloader`.
- Active development belongs on `new-method`. Keep `main` at the pre-modernization baseline unless the user explicitly requests a merge.
- Before editing, run `git status --short --branch` and confirm the repository root with `git rev-parse --show-toplevel`.
- Do not commit build output, virtual environments, `.local/`, IDE state, test HEX artifacts, or production secrets.
- A local safety branch named `backup/pre-new-method-migration-20261002` may exist. Do not delete it unless the user explicitly asks.
- `Bootloader/tiny-AES-c` is an upstream submodule at commit `23856752fbd139da0b8ca6e471a13d5bcc99a08d`. It has no project-specific source modifications. Detached HEAD is normal. Do not push to its upstream repository. On NTFS, keep its local `core.filemode=false` setting to avoid false executable-bit changes.

## Documentation rule

Every functional, build, format, protocol, UI, hardware, or workflow change must update both:

- `README.md` in English
- `README-TR.md` in Turkish

Keep both documents semantically equivalent. Update this file when architectural rules, ownership boundaries, build commands, memory layout, or agent workflow change.

## Project map

- `App/`: sample ATmega328P application used to exercise bootloader entry.
- `Bootloader/`: 4 KB secure bootloader, RS485 protocol, CRC implementation, and tiny-AES-c dependency.
- `Common/image.h`: the complete C ABI shared by App and Bootloader.
- `Tools/image_format.py`: authoritative Python package/header, AES-CTR, CMAC, and Ed25519 format implementation.
- `Tools/encrypt_image.py`: creates the signed encrypted package.
- `Tools/decrypt_image.py`: verification/decryption test utility; never used in the production flash flow.
- `Tools/Flasher/`: PyQt5 GUI, serial protocol parser, retries, version lock, and mode transitions.
- `tests/`: package, protocol, GUI, and AVR/QEMU crypto agreement tests.
- `App/*_Custom.ld` and `Bootloader/*_Custom.ld`: authoritative flash/SRAM placement and size assertions.
- Root `Makefile`: includes the App and Bootloader build files and exposes the normal entry points.

## Ownership boundary

`Common/image.h` must contain only:

- `image_header_t`
- `shared_area_t`
- `BOOT_KEY`

Do not move protocol commands, flash addresses, CRC helpers, application commands, or project-specific constants into `Common/`. App and Bootloader own their other definitions independently.

App needs `image_header_t` for the flash metadata and `shared_area_t` plus `BOOT_KEY` for bootloader entry. Bootloader reads the same ABI. Python mirrors the binary header layout in `Tools/image_format.py`; it does not include C headers.

## Hardware behavior

Target: ATmega328P at 16 MHz.

- UART speed is fixed at 115200 baud in both App and Bootloader.
- RS485 half-duplex direction enable is PD2: high while transmitting, low while receiving.
- Hardware UART remains on PD0/RX and PD1/TX.
- The shared RAM structure has only the 16-bit `boot_key`; there is no baud-rate field.
- App receives the exact `BOOT\n` command, writes `BOOT_KEY` (`0xabcd`) into `.shared_memory`, and resets through the watchdog.
- Bootloader starts the current application only after validating its full-image CMAC. Otherwise it remains available for update.
- Fuse requirements: BOOTRST programmed and BOOTSZ1:0 = 00, placing the 4 KB boot section at `0x7000`.
- The GUI does not program fuses or lock bits.

## Memory map and ABI

| Region | Address | Rule |
| --- | --- | --- |
| Application flash | `0x0000-0x6fff` | 28 KB, 128-byte pages |
| Image header | `0x0100-0x0143` | packed 68-byte `image_header_t` |
| Bootloader flash | `0x7000-0x7fff` | maximum 4096 loaded bytes |
| Shared SRAM | `0x800100-0x800101` | packed 2-byte `shared_area_t` |
| Normal SRAM | `0x800102` onward | `.data`, `.bss`, stack |

The packed image header layout is:

1. `magic`: `uint32_t`
2. `hw_id`: `uint16_t`
3. `sw_major`: `uint8_t`
4. `sw_minor`: `uint8_t`
5. `sw_revision`: `uint8_t`
6. `build_num`: `uint16_t`
7. `image_size`: `uint16_t`
8. `compile_date[12]`
9. `compile_time[9]`
10. `avr_gcc_version[6]`
11. `nonce[12]`
12. `tag[16]`

Total size is 68 bytes and `tag` begins at byte offset 52. The linker scripts assert the object sizes, addresses, SRAM boundary, application boundary, and 4 KB bootloader limit. Never change one representation alone. A header change requires synchronized updates to:

- `Common/image.h`
- App header initializer
- Bootloader size/offset constants and validation
- both linker scripts where applicable
- `Tools/image_format.py`
- GUI display/parsing
- tests
- both README files

There is intentionally no compatibility with the pre-modernization header or package formats.

## Security model

Two verification levels are intentional:

1. PC level: the flasher verifies an Ed25519 signature before accepting a package. The signature covers the clear header, encrypted page data, per-page tags, and package length.
2. AVR level: the bootloader uses its embedded 128-bit device key. Separate encryption and MAC keys are derived from it. Each encrypted page has an AES-CMAC checked before flash is modified, and the completed plaintext image has a full-image AES-CMAC checked before execution.

The application image uses AES-CTR. CRC16 protects RS485 frames against transmission corruption and is not an authenticity mechanism. The AVR must not perform RSA or Ed25519 operations.

The package begins with the clear `AVR2` package magic and contains a clear copy of the image header so the GUI can display metadata before flashing. This package magic is separate from `image_header_t` and is used for package framing/version selection.

Key rules:

- `.local/device_key.hex` and `.local/signing_private.pem` are development secrets and are ignored by Git.
- Never print, commit, or copy key contents into reports or tests.
- Production keys stay outside the repository.
- Historical tracked AES/RSA keys are compromised and must not be reused.
- `Tools/decrypt_image.py` is for testing only.
- The GUI's Force option bypasses only its same/older-version policy. It must never bypass signature, hardware ID, CMAC, or protocol validation.

## Serial update protocol

The Python side is in `Tools/Flasher/protocol.py`; the AVR side is in `Bootloader/protocol.h` and `Bootloader/bootloader.c`.

- Frames use STX, command, payload length, payload, and little-endian CRC16.
- The transfer sequence is header/BEGIN, ordered encrypted pages with per-page tags, then FINISH.
- ACK/NACK includes the page sequence. NACK reasons distinguish malformed packet, state, size, authentication, and image errors.
- The GUI retries timed-out requests.
- Bootloader accepts the immediately repeated page without rewriting flash, allowing recovery from a lost ACK.
- Bootloader briefly accepts a repeated FINISH when its ACK was lost.
- RS485 direction must return to receive only after the final UART bit has left the transmitter.

Preserve retry idempotency when changing commands or state transitions.

## Flasher behavior

- The GUI uses PyQt5 and opens serial ports at 115200 baud.
- Trusted key Browse accepts only Ed25519 public-key PEM files. Changing the key revalidates the selected package.
- File and device panels show software version, hardware ID, compiler version, compile date/time, authentication state, and image size.
- Go Bootloader sends `BOOT\n` and waits for a bootloader header before confirming the transition.
- Go Application sends the reset command and waits for the sample App's `Hello World!!\r\n` banner.
- Same or older firmware is disabled unless Force is selected.
- `Flasher_GUI.py` is generated from `Flasher_GUI.ui`. Keep both synchronized; prefer editing the `.ui` source and regenerating Python with `pyuic5`.
- Windows Qt plugin-path handling in `Tools/Flasher/main.py` is required for Unicode installation/project paths.

## Build environments

WSL/Linux:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
make clean
make all
make test
```

Windows GUI:

```powershell
py -3 -m venv .venv-win
.\.venv-win\Scripts\python.exe -m pip install -r requirements.txt
.\.venv-win\Scripts\python.exe Tools\Flasher\main.py
```

Use separate `.venv` and `.venv-win` directories. Do not reuse one environment across WSL and Windows.

Useful Make targets:

- `make app`
- `make bootloader`
- `make package`
- `make all`
- `make test`
- `make clean`

`make all` must produce:

- `App/Release/App.hex`
- `Bootloader/Release/Bootloader.hex`
- `App/Release/App_encrypted.bin`

Microchip Studio projects must remain usable. When source files move or build flags change, update both Makefiles and `.cproj` files. Studio and avr-gcc builds use the same custom linker scripts.

## Required verification

For changes that affect code, format, protocol, linker layout, crypto, or build configuration:

1. Run `make clean && make all`.
2. Confirm the bootloader's loaded `.text` plus initialized `.data` remains at most 4096 bytes. The linker assertion is the final gate.
3. Run `.venv/bin/python -m unittest discover -s tests -v` or `make test`.
4. Run `git diff --check` and inspect `git status --short`.
5. If package/header code changed, verify a generated package with `Tools/decrypt_image.py`.
6. Keep README.md and README-TR.md updated.

Do not broaden tests without a concrete risk. Preserve the AVR/QEMU agreement test because it checks that Python and actual bootloader AES/CMAC/CTR behavior match.

## Known design limits

- ATmega328P has no second application bank. Power loss during an authenticated update can leave the old application partially erased. The bootloader must reject the invalid image and remain ready for another transfer.
- GUI version locking is not device-enforced anti-rollback.
- Physical access, fuse/lock misconfiguration, signing-key compromise, or device-key extraction are outside the software-only guarantee.
- A package created for the modern format requires the modern bootloader; initial migration from the old format requires ISP programming.
