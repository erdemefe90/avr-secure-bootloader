# AVR Secure Bootloader

Turkish documentation: [README-TR.md](README-TR.md)

Contributor and coding-agent guide: [AGENTS.md](AGENTS.md)

This repository contains a 4 KB bootloader for the ATmega328P, a sample application, and a PyQt5 flasher that communicates over RS485. When the sample application receives `BOOT\n`, it writes `0xabcd` to the 16-bit `boot_key` in `.shared_memory` and enters the bootloader through a watchdog reset. Both programs use a fixed **115200 baud** rate. The shared RAM area has no baud-rate field.

## Setup and build

The repository root is `avr-secure-bootloader/`; in this environment it is `/root/projects/avr-secure-bootloader`. Resolve paths from the actual Git root rather than assuming a fixed Windows/WSL mount.

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
| Bootloader code and initialized data | `0x7000–0x7f5f` | Cannot overlap metadata |
| Bootloader info | `0x7f60–0x7f79` | Packed 26-byte `boot_info_t` |
| Reserved serial erase page | `0x7f80–0x7fff` | No code or initialized data |
| Serial number | `0x7ff0–0x7fff` | 16-byte C string: up to 15 UTF-8 bytes + NUL; defaults to `0xff` |
| Shared SRAM | `0x800100–0x800101` | `.shared_memory`; only `boot_key` |
| Normal SRAM | `0x800102` onward | `.data`, `.bss`, and stack |

The linker scripts use `ASSERT` to check the actual header and shared-object sizes, their addresses, SRAM bounds, and the bootloader flash limit. The entire boot region remains `0x7000–0x7fff` (4096 bytes); loaded-byte accounting includes `.text`, initialized `.data`, `.boot_info`, and `.serial_number`. Separate linker regions and size/address assertions prevent code or data from occupying the metadata or serial erase page. The App linker already ends application loads before `0x7000`. The packager pads the application image to a full page with `0xff`; `image_size` records the padded length. The bootloader checks the image size, hardware ID, and page alignment.

The image header has no separate schema-version field. Package format selection is handled only by the clear-text `AVR3` package magic. The reordered header is incompatible with `AVR2` and pre-modernization layouts. Rebuild and repackage App, and provision the matching bootloader through ISP before using `AVR3` packages.

The packed 68-byte header contains `magic`, `hw_id`, the three software-version bytes, `build_num`, the 12-byte compile date, 9-byte compile time, 6-byte AVR-GCC version, `image_size`, 12-byte AES-CTR nonce, and 16-byte full-image CMAC tag, in that order. The GUI displays the build metadata from both the selected signed package and the detected device.

`Common/image.h` is the complete shared C interface between the application and bootloader. It contains `image_header_t`, `boot_info_t`, `shared_area_t`, `BOOT_KEY`, and the boot-info/serial byte addresses and sizes. Other flash-map, protocol, CRC, and application command definitions live in the project that owns them. Compile date/time start at header offsets 11/23, `image_size` at 38, nonce at 40, and the CMAC tag at 52; the total remains 68 bytes.

Set the ATmega328P fuses to **BOOTRST programmed** and **BOOTSZ1:0 = 00** so that the 4 KB boot section starts at `0x7000`. Configure general ISP lock bits to restrict external access as required. Leave BLB02 unprogrammed so the bootloader can read the application for CMAC, and BLB01 unprogrammed while serial updates are needed. Leave BLB12 unprogrammed for App to read boot metadata; this also permits application-side reads of boot code/key storage. BLB11 can prevent boot-section writes while retaining metadata reads. GUI/CLI read all fuse and lock bits, but program only LB2/LB1 through bootloader SPM. BLB0/BLB1 and fuse writes require ISP; unlocking requires ISP chip erase. Configure fuses and BLB protections through ISP before final LB protection. See the [ATmega328P datasheet](https://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-7810-Automotive-Microcontrollers-ATmega328P_Datasheet.pdf), sections 26–27, and [AVR-LibC boot utilities](https://www.nongnu.org/avr-libc/user-manual/group__avr__boot.html).

## Bootloader metadata and serial number

`BOOT_INFO_ADDRESS` (`0x7f60`) identifies the packed `boot_info_t`: three version bytes, 16-bit `build_num`, `compile_date[12]`, and `compile_time[9]`, in that order. The bootloader currently initializes version `1.1.0+1` and its own compile timestamp. `SERIAL_NUMBER_ADDRESS` (`0x7ff0`) identifies a 16-byte C string: up to 15 UTF-8 bytes followed by NUL. `BOOT_INFO_SIZE` and `SERIAL_NUMBER_SIZE` are 26 and 16. These are **flash byte addresses**, not SRAM addresses; an application can read them without linking bootloader symbols:

```c
#include <avr/pgmspace.h>
#include "image.h"

boot_info_t info;
char serial[SERIAL_NUMBER_SIZE];
memcpy_P(&info, (const void *)BOOT_INFO_ADDRESS, sizeof(info));
memcpy_P(serial, (const void *)SERIAL_NUMBER_ADDRESS, sizeof(serial));
serial[SERIAL_NUMBER_SIZE - 1] = '\0'; /* bounded even for old/erased data */
if ((uint8_t)serial[0] == 0xff) serial[0] = '\0';
```

App sources and its existing linker script are unchanged. The shared header reorder takes effect when App is rebuilt. Provision the serial with the standalone RS485 tool below, or replace exactly the bytes `0x7ff0–0x7fff` in a copy of the bootloader HEX before ISP programming, using at most 15 UTF-8 bytes plus NUL and zero padding. Preserve all other HEX bytes, especially the embedded device key and boot metadata. The default HEX contains `0xff` in this field. Normal signed application updates never write the boot section or serial page. ISP chip erase removes the serial; reprovision it when reinstalling the bootloader. Bootloader HEX files contain the device key and must be handled as provisioning secrets.

### Standalone serial writer

Close the flasher GUI connection so the serial port is free, then run:

```sh
python Tools/write_serial.py --port /dev/ttyUSB0 --serial "DEVICE-001"
```

On Windows:

```powershell
.\.venv-win\Scripts\python.exe Tools\write_serial.py --port COM5 --serial "DEVICE-001"
```

`--serial` accepts nonempty printable UTF-8 text of **at most 15 bytes**, reserving the 16th byte for NUL. You can enter a shorter identifier such as `DEVICE-001`; the writer adds NUL and zero padding automatically. Length is measured in encoded bytes, not characters; embedded NUL/control characters and oversized input are rejected instead of truncated. Readers stop at the first NUL and display only the text, so no manual 16-byte completion is needed. All `0xff` still denotes unprovisioned flash. Changing an existing serial requires `--replace`. An already matching serial is reported as verified without a flash write. The tool uses 115200 baud, listens for bootloader packets for 0.5 seconds, sends `BOOT\n` once if none are detected, and confirms entry from HEADER/INFO packets. It reads current serial/lock status before writing. Timed-out or malformed requests are retried with identical contents. Success requires an ACK and a matching serial readback; failures return exit code 1. The device remains in bootloader mode after provisioning. This tool has no Qt dependency and sends no firmware, fuse, lock, or reset commands.

The matching bootloader must be installed through ISP first. Boot-section write protection (BLB11) blocks serial changes: provision the serial **before** applying this lock. Reconnect the GUI to see the saved serial text in **Bootloader info → Serial number**. The main flasher displays the serial; writing belongs to this separate tool.

`CMD_SERIAL` (`0xba`) carries the expected current serial followed by the new serial (16 bytes each), with ACK/NACK sequence `0xfffd`. The bootloader rejects a changed current serial, active firmware transfer/FINISH grace, malformed length, or boot write protection. Repeating an already written value ACKs without rewriting. Only the reserved page at `0x7f80` is erased/written; its first 112 bytes are preserved, the last 16 bytes are replaced with the NUL-terminated serial field, and all 128 bytes are verified before ACK. The bootloader rejects a new field with an empty first byte or a nonzero final byte. No request supplies a flash address. Serial provisioning uses CRC rather than cryptographic authentication; restrict serial service access. Power loss can lose the serial but cannot erase App, boot code, or boot metadata through this command.

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

The application handles PyQt5's platform-plugin path explicitly on Windows, including project paths that contain non-ASCII characters. It sets a dedicated AppUserModelID before creating QApplication and loads application/window and Browse icons from absolute paths next to main.py, so launching from another working directory uses the AVR icon instead of grouping with Python. See [Microsoft’s startup requirement](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-setcurrentprocessexplicitappusermodelid). To launch the GUI without a console, use `.\.venv-win\Scripts\pythonw.exe Tools\Flasher\main.py`; CLI commands use python.exe so their output remains visible.

Connect to the serial port. If the application is running, click **Go Bootloader** to send `BOOT\n`. The GUI confirms the transition when it receives a bootloader header. **Go Application** is available only while the bootloader is detected. It sends the reset command, clears cached device information, and reports that application startup was requested. It does not wait for or interpret application output. Bootloader-entry requests still require a bootloader header and report a timeout if it does not arrive. The serial speed is fixed at 115200 baud.

Use **Trusted key / Browse** to select the Ed25519 public key that is allowed to verify firmware packages. Select a signed `.bin` package and click **Flash**. After signature verification, the GUI displays the version, hardware ID, compile date/time, AVR-GCC version, and size from the package header. By default, it disables Flash for an image with the same or an older version than the detected device image. **Force** overrides only this GUI version rule; it does not bypass signature, hardware ID, or AVR CMAC checks. The GUI rule is not a device-enforced anti-rollback mechanism. Flash also requires current bootloader status with application read/write permissions; Force cannot override hardware locks. Firmware/key selection and flash-protection controls are disabled during a transfer.

## Fuse reads and hardware lock programming

When the bootloader is detected, the GUI displays its version and compile timestamp, the serial as text (`Not provisioned` for all `0xff`, `Invalid serial format` for an invalid or unterminated string), low/high/extended fuse bytes, the raw lock byte, application and boot write permissions, and ISP protection. **Read fuses / locks** refreshes these values and sets the LB2/LB1 selector to the physical modes returned by the device. The first status response and lock-programming readback also synchronize the selector. Periodic idle status preserves unsubmitted user choices. A reserved LB pair selects Keep current and remains identified as reserved in the status display; no lock write is sent by refreshing. The GUI identifies incorrect BOOTRST/BOOTSZ settings and read locks that prevent full-image CMAC or App metadata access. Status is cleared on disconnect or an application-start request. Incoming bytes are parsed only as bootloader frames; application text is ignored and never used as mode detection.

**Apply lock…** programs only the LB2/LB1 target in the Fuses / locks tab. BLB0/BLB1 and all fuse bytes remain visible as read-only status. A permanent-lock confirmation lists the selected LB mode and its effects. LB Mode 2 blocks ISP flash/EEPROM programming and fuse writes; Mode 3 also blocks ISP verification and boot-lock writes. LB protection alone preserves bootloader application updates and serial writes, subject to the existing BLB permissions. After programming, the GUI compares all six physical lock bits with the expected state, including unchanged BLB bits, and displays the readback. Unlocking requires ISP chip erase, which erases firmware and serial; reinstall the bootloader/application and reprovision the serial.

`CMD_INFO` (`0xb8`, empty request) returns 46 bytes: 26-byte boot info, 16-byte serial, then low fuse, high fuse, extended fuse, and lock bytes. It is also sent at bootloader entry and while idle. `CMD_LOCK` (`0xb9`) takes one nonzero programming mask limited to bits 1..0 (`0x03`): mask bits set to 1 program the corresponding LB bit to 0 (LB2=1, LB1=0). Every other bit, including all BLB bits, and a resulting reserved LB2/LB1=`01` are rejected. Mask `0x01` selects LB Mode 2 from Mode 1; `0x03` selects Mode 3; `0x02` advances Mode 2 to Mode 3. Old BLB masks `0x04`, `0x10`, `0x14` are rejected. No mask can change a physical 0 back to 1. Lock ACK/NACK uses sequence `0xfffe`; `NACK_LOCK` is 6. The bootloader verifies physical readback before ACK, rejects locking during an active transfer or FINISH grace, and safely accepts repeated lock masks after a lost ACK. BEGIN rejects locked application reads or writes. Lock/status control frames use CRC rather than cryptographic authentication; restrict serial service access because a lock request can stop updates until ISP recovery.

## Lock groups and CLI control

The GUI has separate **Bootloader info** and **Fuses / locks** tabs. Bootloader info contains only version, compile timestamp and serial. The lock tab shows fuse bytes, the raw lock byte, and each group’s physical bits, mode and permissions. A bit value of `0` means programmed. BLB0/BLB1 Modes 1–4 are displayed but cannot be written from GUI/CLI or CMD_LOCK; configure them through ISP. Only LB2/LB1 has a target selector, offering Keep current and Modes 1–3, never reserved `01`. GUI/CLI reject every transition requiring 0 → 1; choosing a mode already set is a no-op. LB progresses 1 → 2 → 3 or 1 → 3. Mode 1 never unlocks a locked device. If an existing LB pair is reserved `01`, LB Mode 3 can repair it without altering BLB bits.

| Mode | Physical pair | BLB0: BLB02 / BLB01 | BLB1: BLB12 / BLB11 |
| --- | --- | --- | --- |
| 1 | `11` | App writes and Boot → App reads allowed | Boot writes and App → Boot reads allowed |
| 2 | `10` | App writes blocked; Boot → App reads allowed | Boot/serial writes blocked; App → Boot reads allowed |
| 3 | `00` | App writes and Boot → App reads blocked | Boot/serial writes and App → Boot reads blocked |
| 4 | `01` | Boot → App reads blocked; App writes allowed | App → Boot reads blocked; Boot writes allowed |

| LB mode | LB2 / LB1 | ISP effect |
| --- | --- | --- |
| 1 | `11` | Programming and verification allowed |
| 2 | `10` | Programming blocked |
| 3 | `00` | Programming and verification blocked |
| Reserved | `01` | Do not use |

LB protection controls external programming/verification; it does **not** by itself block bootloader SPM updates. BLB0 controls those application writes. BLB1 controls boot-section/serial writes. Read-lock modes also affect interrupts as described in the [ATmega328P datasheet](https://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-7810-Automotive-Microcontrollers-ATmega328P_Datasheet.pdf), tables 26-2, 26-3 and 27-2. The ATmega328P supports LB2/LB1 programming by SPM (datasheet section 26.8.7); this protocol deliberately exposes only those two bits. BLB and fuse writes require ISP. Unlocking hardware protection requires chip erase. Install the matching bootloader through ISP to enforce the LB-only command mask; previously provisioned bootloaders retain their original command policy until replaced.

Running the flasher without arguments opens the GUI. Providing a command runs the CLI **without importing Qt**. For example, with your Python environment active:

```sh
python Tools/Flasher/main.py ports
python Tools/Flasher/main.py verify --file App/Release/App_encrypted.bin --key .local/signing_public.pem
python Tools/Flasher/main.py info --port COM5
python Tools/Flasher/main.py bootloader --port COM5
python Tools/Flasher/main.py flash --port COM5 --file App/Release/App_encrypted.bin --key .local/signing_public.pem
python Tools/Flasher/main.py application --port COM5
```

Use `/dev/ttyUSB0` instead of `COM5` on Linux. On Windows, run these commands with `.\.venv-win\Scripts\python.exe`. The equivalent module entry point is `python -m Tools.Flasher.cli`. `info`, `bootloader`, `flash` and `lock` first listen for bootloader packets for 0.5 seconds. If no header arrives, they send `BOOT\n` once and confirm entry from HEADER/INFO; no application banner is needed. A general application must implement this entry command or be put into bootloader mode externally. `application` sends RESET and returns as soon as the serial write succeeds, without waiting for device output. Its JSON reports `application_start: requested`, `confirmed: false`, and `mode: unknown`. Successful transmission does not prove that an application actually started; the bootloader still enforces image CMAC before execution. Close the GUI's port connection before using CLI commands.

`verify` runs offline. `flash` verifies the Ed25519 signature **before opening the serial port**, checks hardware ID, current application read/write permissions and the same/newer version rule, then sends BEGIN, ordered encrypted pages and FINISH. `--force` bypasses only the version rule. Packets are retried up to five times; stale/duplicate ACKs cannot advance the transfer and authentication/image/lock NACKs stop it. `--timeout SECONDS` sets the response timeout (default 2); FINISH gets at least 8 seconds. GUI and CLI share package/version/lock policy. A FINISH ACK reports verified firmware; application startup follows the bootloader's grace period and is not yet confirmed by that ACK.

CLI lock programming requires `--lb-mode 1|2|3` and explicit confirmation with `--yes`. The following applies LB Mode 3, blocking ISP programming/verification while preserving bootloader updates when BLB0 permits application reads/writes:

```sh
python Tools/Flasher/main.py lock --port COM5 --lb-mode 3 --yes
```

Use `--lb-mode 2` to block ISP programming while retaining ISP verification, or `--lb-mode 3` to block both. BLB write options are not accepted. Mode 1 is accepted only when LB is already unlocked. The tool prints LB effects to stderr, rejects every transition requiring bit unlocking before sending CMD_LOCK, preserves BLB0/BLB1, and verifies all six bits after programming. Successful commands emit JSON on stdout; flash progress and errors go to stderr. Exit codes are 0 for success, 1 for runtime/verification failure, and 2 for invalid arguments. CLI info returns the decoded serial string without padding; `serial_valid` reports whether it is valid text. Erased or invalid fields yield `serial: null`; old binary serials can be replaced with `--replace`. Serial-number writing remains in the separate `Tools/write_serial.py` tool.

## Tool CLI reference

Run these examples from the repository root with the Python environment active; replace `COM5` with `/dev/ttyUSB0` on Linux, or use `.\.venv-win\Scripts\python.exe` in Windows PowerShell. The commands below are independent usage examples; choose the operation you need. Close the GUI connection before another tool opens the same port. Paths under `.local` are development examples; production key paths must be outside the repository.

| Tool | Arguments and behavior |
| --- | --- |
| `Tools/ensure_keys.py` | `DIRECTORY`; creates missing development device/signing keys and writes the public key when generating the signing key. Existing private keys are retained. `make all` normally calls it automatically. |
| `Tools/key_header.py` | `KEY_HEX OUTPUT_HEADER`; creates the private C initializer used by the bootloader build. Keep its output in ignored build storage. Make/Studio normally run this step. |
| `Tools/encrypt_image.py` | `-f APP_HEX --device-key KEY_HEX --signing-key PRIVATE_PEM [-o PACKAGE_BIN]`; signs/encrypts an application. Default output: `<input-stem>_encrypted.bin`. Requires a built App HEX. |
| `Tools/decrypt_image.py` | `-f PACKAGE_BIN --device-key KEY_HEX --verify-key PUBLIC_PEM [-o PLAIN_BIN]`; test-only signature/CMAC verification and decryption. Default output: `<package-stem>.plain.bin`. Never use it in production flashing. |
| `Tools/Flasher/main.py` | No arguments: GUI. Commands: `ports`, `verify`, `info`, `bootloader`, `application`, `flash`, `lock`. `verify` needs `--file` and optional `--key`; port commands need `--port`, with optional `--timeout` (default 2 seconds). `flash` also needs `--file`, optional `--key` and `--force` (version policy only). `lock` requires `--lb-mode {1,2,3} --yes`. |
| `Tools/write_serial.py` | `--port PORT --serial TEXT [--replace] [--timeout SECONDS]`; standalone serial provisioning, 1..15 printable UTF-8 bytes, automatic NUL/padding, default timeout 2 seconds. `--replace` explicitly allows an existing serial to change. |

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

For per-command help, run `python Tools/Flasher/main.py --help` or `python Tools/Flasher/main.py COMMAND --help`; each standalone tool also supports `--help`. The headless flasher has equivalent entry points `python Tools/Flasher/cli.py COMMAND ...` and `python -m Tools.Flasher.cli COMMAND ...`. `image_format.py`, `policy.py`, `protocol.py`, and generated `Flasher_GUI.py` are libraries/UI support, without standalone CLIs. Flasher commands emit JSON to stdout and errors/progress to stderr (exit 0 success, 1 runtime failure, 2 argument error). The serial writer emits `Serial verified: TEXT` on success (exit 0), errors to stderr (exit 1; invalid arguments 2). `--force` never overrides authentication, hardware ID or physical locks.

## Security and power-loss limits

Earlier revisions tracked an AES key and an RSA private key. They remain accessible in Git history and must never be used in production. Generate new production keys and provision devices again. The current `AVR3` header/package is incompatible with `AVR2` and older bootloaders, so migration requires an ISP programmer. Configure the appropriate fuse and lock bits to protect the bootloader's embedded AES key from readout.

The ATmega328P has no second application bank. Unauthenticated pages are rejected before writing, but a power loss after a valid update begins can leave the previous application partly erased. The bootloader will not start an invalid image and remains available for another update. Physical access and compromise of either the signing private key or the device AES key are outside the guarantees of this design.
