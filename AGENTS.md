# AGENTS.md

This file is the working guide for coding agents and maintainers. Read it before changing the repository. The public project overview remains in `README.md` and `README-TR.md`.

## Repository and Git workflow

- The repository root is `avr-secure-bootloader/`; in this environment it is `/root/projects/avr-secure-bootloader`. Resolve paths from the actual Git root rather than assuming a fixed Windows/WSL mount.
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
- `Tools/write_serial.py`: standalone RS485 serial-number provisioner accepting short serial text; no Qt or firmware flashing, with readback, retries, and explicit `--replace` for existing serials.
- `Tools/Flasher/`: PyQt5 GUI, headless `cli.py`, shared `policy.py`, serial protocol parser, retries, version lock, and mode transitions.
- `tests/`: package, protocol, GUI, and AVR/QEMU crypto agreement tests.
- `App/*_Custom.ld` and `Bootloader/*_Custom.ld`: authoritative flash/SRAM placement and size assertions.
- Root `Makefile`: includes the App and Bootloader build files and exposes the normal entry points.

## Ownership boundary

`Common/image.h` must contain only:

- `image_header_t`
- `boot_info_t`
- `shared_area_t`
- `BOOT_KEY`
- `BOOT_INFO_ADDRESS`, `BOOT_INFO_SIZE`, `SERIAL_NUMBER_ADDRESS`, `SERIAL_NUMBER_SIZE`

The boot-info and serial-number flash byte addresses/sizes are shared so applications can read them with `memcpy_P` or `pgm_read_*`. Other flash-map constants, protocol commands, CRC helpers, application commands, and project-specific constants remain owned independently by App and Bootloader.

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
- The GUI reads all fuse bytes and lock bits through the bootloader. GUI/CLI program only LB2/LB1 through ATmega328P SPM after explicit permanent-lock confirmation. BLB0/BLB1 and fuses are read-only in GUI/CLI and CMD_LOCK; configure them through ISP. Hardware locks only change 1 to 0; unlocking requires ISP chip erase. Existing BLB0 Modes 3/4 block CMAC/application startup; BLB1 Modes 3/4 block App reads of boot metadata/serial. LB protection alone must not block SPM updates or serial writes.

## Memory map and ABI

| Region | Address | Rule |
| --- | --- | --- |
| Application flash | `0x0000-0x6fff` | 28 KB, 128-byte pages |
| Image header | `0x0100-0x0143` | packed 68-byte `image_header_t` |
| Bootloader flash | `0x7000-0x7fff` | maximum 4096 loaded bytes including metadata/serial |
| Bootloader code and initialized data | `0x7000-0x7f5f` | cannot overlap metadata |
| Bootloader info | `0x7f60-0x7f79` | packed 26-byte `boot_info_t` |
| Serial erase page | `0x7f80-0x7fff` | no code/data; serial occupies only last 16 bytes |
| Serial number | `0x7ff0-0x7fff` | 16-byte C string: 1..15 UTF-8 bytes + NUL, default `0xff`, provision through RS485 or ISP |
| Shared SRAM | `0x800100-0x800101` | packed 2-byte `shared_area_t` |
| Normal SRAM | `0x800102` onward | `.data`, `.bss`, stack |

The packed image header layout is:

1. `magic`: `uint32_t`
2. `hw_id`: `uint16_t`
3. `sw_major`: `uint8_t`
4. `sw_minor`: `uint8_t`
5. `sw_revision`: `uint8_t`
6. `build_num`: `uint16_t`
7. `compile_date[12]`
8. `compile_time[9]`
9. `avr_gcc_version[6]`
10. `image_size`: `uint16_t`
11. `nonce[12]`
12. `tag[16]`

Total size is 68 bytes; compile date/time begin at offsets 11/23, `image_size` at 38, and `tag` at 52. `boot_info_t` contains version bytes, `build_num`, `compile_date[12]`, and `compile_time[9]`, in that order. Its address and size, plus the serial address and size, are asserted by the bootloader linker script. The App script already excludes the entire boot region. Bootloader loaded-byte accounting includes `.boot_info` and `.serial_number` as well as `.text` and initialized `.data`. The linker scripts assert the object sizes, addresses, SRAM boundary, application boundary, and 4 KB bootloader limit. Never change one representation alone. A header change requires synchronized updates to:

- `Common/image.h`
- App header initializer if necessary (its designated fields need no edit for a reorder)
- Bootloader size/offset constants and validation
- both linker scripts where applicable
- `Tools/image_format.py`
- GUI display/parsing
- tests
- both README files

The current package magic is `AVR3`. Reordered headers are incompatible with `AVR2` and pre-modernization formats; rebuild and repackage App and provision the matching bootloader through ISP. Do not change App functionality just to exercise metadata reads.

## Security model

Two verification levels are intentional:

1. PC level: the flasher verifies an Ed25519 signature before accepting a package. The signature covers the clear header, encrypted page data, per-page tags, and package length.
2. AVR level: the bootloader uses its embedded 128-bit device key. Separate encryption and MAC keys are derived from it. Each encrypted page has an AES-CMAC checked before flash is modified, and the completed plaintext image has a full-image AES-CMAC checked before execution.

The application image uses AES-CTR. CRC16 protects RS485 frames against transmission corruption and is not an authenticity mechanism. The AVR must not perform RSA or Ed25519 operations.

The package begins with the clear `AVR3` package magic and contains a clear copy of the image header so the GUI can display metadata before flashing. This package magic is separate from `image_header_t` and is used for package framing/version selection.

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

- `CMD_INFO` (`0xb8`) reports 26-byte boot metadata, 16-byte serial, then low/high/extended fuse and lock bytes (46 bytes total); sent on entry, while idle, and on request.
- `CMD_LOCK` (`0xb9`) accepts one nonzero mask limited to LB2/LB1 bits 1..0 (`0x03`). Mask bits set to 1 program their physical bit to 0. Reject every BLB/reserved bit and a resulting LB2/LB1=01. ACK/NACK uses sequence `0xfffe`; `NACK_LOCK` is 6. Active transfers and FINISH grace reject locking. Read back physical bits before ACK; repeated masks are idempotent. Preserve BLB0/BLB1 and keep their physical status display. LB2/LB1 are SPM-programmable on ATmega328P (datasheet section 27.8.7; automotive edition 26.8.7). Do not restore BLB writing through this protocol.
- `CMD_SERIAL` (`0xba`) takes exactly 32 bytes: expected current serial then new serial (16 each). ACK/NACK uses sequence `0xfffd`. The new serial is a nonempty NUL-terminated string; byte 15 must be zero. PC tools accept 1..15 printable UTF-8 bytes, automatically NUL/zero-pad to 16, reject oversized/control/NUL-containing input, and display only text before NUL. Reject active transfers/FINISH grace, stale expected serials, invalid new serial fields, and boot write protection. If the requested serial already matches, ACK without erasing. Otherwise preserve the first 112 bytes of the reserved last page, replace the last 16, write only page `0x7f80`, and verify all 128 bytes. Never accept a flash address from this command.
- After a control ACK, wait for the next request rather than immediately transmitting unsolicited INFO, so the host's readback request cannot collide on half-duplex RS485. The serial writer waits for both HEADER and INFO in the initial burst before transmitting. Periodic idle INFO and explicit INFO requests report the saved serial.
- BEGIN rejects application read or write protection (including BLB0 Mode 4), because completed images must remain readable for CMAC. Force must not bypass it. No hardware unlock command exists.
- Control/status/serial-provisioning frames use CRC, not cryptographic authentication. Restrict serial service access; locks can stop updates until ISP recovery and serial requests can change device identity. Provision the serial before programming BLB11, which also blocks serial writes. Power loss during serial programming can lose the serial, but only the reserved page is erased; App and boot code/metadata are outside it.

Preserve retry idempotency when changing commands or state transitions.

## Flasher behavior

- The GUI uses PyQt5 and opens serial ports at 115200 baud.
- Trusted key Browse accepts only Ed25519 public-key PEM files. Changing the key revalidates the selected package.
- File and device panels show software version, hardware ID, compiler version, compile date/time, authentication state, and image size.
- Go Bootloader sends `BOOT\n` and waits for a bootloader header before confirming the transition.
- Go Application sends the reset command, clears cached bootloader/device information, and reports only that application startup was requested. Do not inspect application banners or require any application output. Keep the App example unchanged. Bootloader entry still requires a header/INFO response; CLI and serial writer listen for 0.5 seconds before sending `BOOT\n` once if no header is detected. Applications must implement that entry command or enter bootloader mode externally.
- Same or older firmware is disabled unless Force is selected. Flash also requires current device information with application read/write permissions; Force cannot override hardware locks. Clear status on disconnect or an application-start request.
- Serial display uses plain text (never Qt rich text). Decode UTF-8 through the first NUL; report erased fields as Not provisioned and malformed/unterminated fields as Invalid serial format. CLI info emits serial text or null plus serial_valid; binary/raw values stay internal for compare-and-write.
- Separate Bootloader info and Fuses / locks tabs. The first shows version/date/time/serial; the second shows fuse/raw lock bytes and read-only BLB0/BLB1 physical bits, modes and permissions. BLB pairs decode 11/10/00/01 to Modes 1/2/3/4; LB2/LB1 decode 11/10/00 to Modes 1/2/3 and 01 is reserved. Only LB2/LB1 has a writable target selector (Keep current, Modes 1–3). GUI/CLI share LB transition validation: reject 0-to-1 targets, allow already-set modes as no-ops, and never target reserved LB=01. Apply lock requires explicit GUI confirmation of LB effects, then readback verifies all six bits including unchanged BLB pairs. Read fuses / locks refreshes all displayed status with retries and synchronizes the LB selector to its physical mode. First status and post-lock readback also synchronize; periodic INFO must preserve unsubmitted LB choices. For reserved LB=01 select Keep current. Disable controls during flashing or mode/control requests. LB protection alone must not disable SPM updates.
- With no arguments, `Tools/Flasher/main.py` launches the GUI. Commands run `cli.py` before any Qt import: ports, verify, info, bootloader, application, flash, lock. Support direct script and module entry points. Verify signatures before opening a port for flash; GUI/CLI share package/version/lock policy. Preserve timed-out request retries and ACK sequence filtering; FINISH gets at least 8 seconds. CLI lock requires `--lb-mode 1..3` and `--yes`, then hardware readback; BLB write options must be rejected before opening a port. Print LB effects on stderr and preserve all BLB bits. Emit JSON on stdout, progress/errors on stderr, exit 0/1/2 for success/runtime/arguments. The CLI application command sends RESET without mode detection or waiting for a reply; return JSON application_start=requested, confirmed=false, mode=unknown. Never claim successful transmission confirms execution. Serial writing stays in the standalone tool.
- `Flasher_GUI.py` is generated from `Flasher_GUI.ui`. Keep both synchronized; prefer editing the `.ui` source and regenerating Python with `pyuic5`.
- Windows Qt plugin-path handling in `Tools/Flasher/main.py` is required for Unicode installation/project paths. Set the dedicated AppUserModelID before QApplication creation; load application/window and Browse icons from absolute paths relative to main.py, independent of CWD. Preserve CLI dispatch before Qt/Windows GUI setup. Windows taskbar behavior needs native Windows verification; Linux tests cover icon loading and the mocked API call order.

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

## Tool CLI usage

Run from the repository root with the appropriate active environment. The following are independent examples, not an instruction to provision or lock hardware during verification. Use `/dev/ttyUSB0` on Linux or `COM5` on Windows. Windows command invocations use `.\.venv-win\Scripts\python.exe`; GUI-only invocations may use pythonw.exe. Close another tool’s serial connection before opening the same port. `.local` paths below are development examples; production keys remain external.

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

- `ensure_keys.py DIRECTORY`: creates missing development keys; public PEM is generated with a new signing key; existing private keys remain. Normally run by Make.
- `key_header.py KEY_HEX OUTPUT_HEADER`: emits a secret C initializer to ignored build output; normally run by Make/Studio. Never print or track it.
- `encrypt_image.py -f APP_HEX --device-key KEY_HEX --signing-key PRIVATE_PEM [-o PACKAGE_BIN]`: signs and encrypts a built application; default `<input-stem>_encrypted.bin`.
- `decrypt_image.py -f PACKAGE_BIN --device-key KEY_HEX --verify-key PUBLIC_PEM [-o PLAIN_BIN]`: test-only signature/CMAC verification and plaintext extraction; default `<package-stem>.plain.bin`; excluded from production flash flow.
- Flasher commands: `ports`; `verify --file PACKAGE [--key PUBLIC_PEM]`; `info|bootloader|application --port PORT [--timeout SECONDS]`; `flash --port PORT --file PACKAGE [--key PUBLIC_PEM] [--force] [--timeout SECONDS]`; `lock --port PORT --lb-mode {1,2,3} --yes [--timeout SECONDS]`. Timeout defaults to 2 seconds; FINISH has an 8-second minimum. The default trusted key is `.local/signing_public.pem` or `AVR_TRUSTED_PUBLIC_KEY`. Force affects version policy only; BLB options must not exist. Equivalent headless entry points: `python Tools/Flasher/cli.py COMMAND ...`, `python -m Tools.Flasher.cli COMMAND ...`. No arguments to main.py opens the GUI. Use `main.py --help` or `main.py COMMAND --help` to inspect help without Qt.
- `write_serial.py --port PORT --serial TEXT [--replace] [--timeout SECONDS]`: serial-only service with readback, 1..15 printable UTF-8 bytes, automatic NUL/padding, timeout default 2 seconds. Replacement requires explicit --replace. Successful output is `Serial verified: TEXT`, exit 0; runtime errors stderr/exit 1; argument errors exit 2.
- Every standalone Python tool supports `--help`. `image_format.py`, `policy.py`, `protocol.py`, and generated `Flasher_GUI.py` are support modules with no standalone CLI. Flasher stdout is JSON, stderr is progress/errors; exit codes 0/1/2 mean success/runtime/arguments.
- Existing build commands are listed above. `make all` uses avr-gcc, avr-objcopy, avr-size and both custom linker scripts; `make test` uses unittest and the AVR/QEMU agreement harness. For production builds use `make all DEVICE_KEY_FILE=/secure/device_key.hex SIGNING_KEY_FILE=/secure/signing_private.pem`; pass the corresponding public PEM to the flasher. Production key creation: `openssl rand -hex 16 > /secure/device_key.hex`, `openssl genpkey -algorithm ED25519 -out /secure/signing_private.pem`, `openssl pkey -in /secure/signing_private.pem -pubout -out /secure/signing_public.pem`; restrict private file permissions (`chmod 600` on Linux). Never execute these examples against existing production keys without an explicit provisioning task.

## Required verification

For changes that affect code, format, protocol, linker layout, crypto, or build configuration:

1. Run `make clean && make all`.
2. Confirm the bootloader's loaded `.text`, initialized `.data`, `.boot_info`, and `.serial_number` remain at most 4096 bytes, and code/data end before `0x7f60`. The linker assertion is the final gate.
3. Run `.venv/bin/python -m unittest discover -s tests -v` or `make test`.
4. Run `git diff --check` and inspect `git status --short`.
5. If package/header code changed, verify a generated package with `Tools/decrypt_image.py`.
6. Keep README.md and README-TR.md updated.

Do not broaden tests without a concrete risk. Preserve the AVR/QEMU agreement test because it checks that Python and actual bootloader AES/CMAC/CTR behavior match.

## Known design limits

- ATmega328P has no second application bank. Power loss during an authenticated update can leave the old application partially erased. The bootloader must reject the invalid image and remain ready for another transfer.
- GUI version locking is not device-enforced anti-rollback.
- Physical access, fuse/lock misconfiguration, signing-key compromise, or device-key extraction are outside the software-only guarantee.
- `AVR3` requires the matching bootloader; migration from `AVR2` or older formats requires ISP programming.
- Hardware locks only transition from 1 to 0; unlocking requires ISP chip erase and reprovisioning firmware, keys, and serial. BLB12 must remain unprogrammed for App to read boot metadata; it cannot protect the embedded key from application-side LPM while leaving these reads available.
