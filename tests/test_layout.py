"""Verify the emitted flash ABI and exercise the linker's overlap gates."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from intelhex import IntelHex

from Tools.Flasher.protocol import DeviceInfo, INFO_FORMAT
from Tools.image_format import HEADER_FORMAT, HEADER_OFFSET, HEADER_SIZE, Header
import struct

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("avr-gcc"), "AVR GCC is required")
class FlashLayoutTests(unittest.TestCase):
    def test_c_header_matches_python_offsets_and_public_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "abi.c"
            source.write_text('''
#include <stddef.h>
#include "image.h"
#define CHECK(name, condition) typedef char name[(condition) ? 1 : -1]
CHECK(header_size, sizeof(image_header_t) == 68);
CHECK(hw_major_offset, offsetof(image_header_t, hw_major) == 4);
CHECK(hw_minor_offset, offsetof(image_header_t, hw_minor) == 5);
CHECK(version_offset, offsetof(image_header_t, sw_major) == 6);
CHECK(build_offset, offsetof(image_header_t, build_num) == 9);
CHECK(date_offset, offsetof(image_header_t, compile_date) == 11);
CHECK(time_offset, offsetof(image_header_t, compile_time) == 23);
CHECK(compiler_offset, offsetof(image_header_t, avr_gcc_version) == 32);
CHECK(size_offset, offsetof(image_header_t, image_size) == 38);
CHECK(nonce_offset, offsetof(image_header_t, nonce) == 40);
CHECK(tag_offset, offsetof(image_header_t, tag) == 52);
CHECK(boot_size, sizeof(boot_info_t) == BOOT_INFO_SIZE && BOOT_INFO_SIZE == 26);
CHECK(boot_address, BOOT_INFO_ADDRESS == 0x7f60);
CHECK(serial_address, SERIAL_NUMBER_ADDRESS == 0x7ff0 && SERIAL_NUMBER_SIZE == 16);
CHECK(shared_size, sizeof(shared_area_t) == 2);
CHECK(image_magic, IMAGE_MAGIC == 0xefefefefUL);
CHECK(header_address, IMAGE_HEADER_ADDRESS == 0x100);
CHECK(app_limit, BOOT_START_ADDRESS == 0x7000);
CHECK(shared_address, SHARED_AREA_ADDRESS == 0x100);
CHECK(boot_baud, BOOT_UART_BAUD == 115200UL);
CHECK(command_length, sizeof(BOOT_COMMAND) == 6);
''')
            result = subprocess.run(["avr-gcc", "-mmcu=atmega328p", f"-I{ROOT / 'Common'}",
                                     "-c", str(source), "-o", str(Path(directory) / "abi.o")],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_independent_app_build_needs_only_public_c_header(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            shutil.copyfile(ROOT / "Common/image.h", project / "image.h")
            # A developer's project still owns its linker configuration. Use the
            # reference layout without access to either project's C sources.
            shutil.copyfile(ROOT / "App/App_Custom.ld", project / "application.ld")
            (project / "main.c").write_text('''
#include <avr/pgmspace.h>
#include "image.h"
volatile shared_area_t shared_area SHARED_AREA_SECTION;
const image_header_t header IMAGE_HEADER_SECTION = {
    .magic = IMAGE_MAGIC, .hw_major = 3, .hw_minor = 1,
    .sw_major = 7, .sw_minor = 8, .sw_revision = 9, .build_num = 42,
    .compile_date = __DATE__, .compile_time = __TIME__,
    .avr_gcc_version = __VERSION__,
};
int main(void) {
    boot_info_t info;
    char serial[SERIAL_NUMBER_SIZE];
    shared_area.boot_key = 0;
    memcpy_P(&info, (const void *)BOOT_INFO_ADDRESS, sizeof(info));
    memcpy_P(serial, (const void *)SERIAL_NUMBER_ADDRESS, sizeof(serial));
    if (info.sw_major == 255 && serial[0] == 'B') bootloader_request();
    for (;;) { }
}
''')
            result = subprocess.run([
                "avr-gcc", "-mmcu=atmega328p", "-std=gnu99", "-Os", "-flto",
                "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-fdata-sections",
                "main.c", "-Wl,--gc-sections,--relax", "-Wl,-Tapplication.ld",
                "-Wl,-section-start=.data=0x800102", "-o", "app.elf"],
                cwd=project, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            subprocess.run(["avr-objcopy", "-O", "ihex", "-R", ".eeprom", "app.elf", "app.hex"],
                           cwd=project, check=True, capture_output=True)
            image = IntelHex(str(project / "app.hex"))
            header = Header(*struct.unpack(HEADER_FORMAT, bytes(image.tobinarray(
                start=HEADER_OFFSET, size=HEADER_SIZE))))
            self.assertEqual(header.version, "7.8.9+42")
            self.assertEqual(header.magic, 0xefefefef)
            self.assertLess(image.maxaddr(), 0x7000)

    def test_generated_flash_metadata_and_header(self):
        boot_path = ROOT / "Bootloader/Release/Bootloader.hex"
        app_path = ROOT / "App/Release/App.hex"
        if not boot_path.exists() or not app_path.exists():
            self.skipTest("build App and Bootloader first")
        boot = IntelHex(str(boot_path))
        self.assertEqual(boot.minaddr(), 0x7000)
        self.assertEqual(boot.maxaddr(), 0x7fff)
        raw = bytes(boot.tobinarray(start=0x7f60, size=26))
        info = DeviceInfo.from_bytes(raw + b"\xff" * 16 + b"\xff\xd8\xfd\xff")
        self.assertEqual((info.sw_major, info.sw_minor, info.sw_revision, info.build), (2, 1, 0, 123))
        self.assertRegex(info.compile_date.rstrip(b"\0").decode(), r"^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{4}$")
        self.assertRegex(info.compile_time.rstrip(b"\0").decode(), r"^[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        self.assertEqual(bytes(boot.tobinarray(start=0x7ff0, size=16)), b"\xff" * 16)
        # The remainder of the serial's erase page has no loaded code or data.
        self.assertFalse(set(range(0x7f80, 0x7ff0)) & set(boot.addresses()))
        app = IntelHex(str(app_path))
        values = struct.unpack(HEADER_FORMAT,
                               bytes(app.tobinarray(start=HEADER_OFFSET, size=HEADER_SIZE)))
        header = Header(*values)
        self.assertEqual(header.version, "1.0.2+123")
        self.assertEqual((header.hw_major, header.hw_minor), (3, 1))
        self.assertEqual(header.hardware_version, "3.1")
        self.assertEqual(header.image_size, 0)  # packaging fills size/nonce/tag
        self.assertRegex(header.compile_date.rstrip(b"\0").decode(), r"^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{4}$")
        self.assertEqual(len(raw), struct.calcsize(INFO_FORMAT) - 20)

    def test_linker_rejects_wrong_sizes_and_code_data_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "layout.S"
            output = Path(directory) / "layout.elf"
            for label, text_size, data_size, info_size, serial_size, expected in (
                ("valid", 2, 0, 26, 16, None),
                ("code overlap", 0xf62, 0, 26, 16, "region"),
                ("data overlap", 2, 0xf60, 26, 16, "overlaps metadata"),
                ("missing info", 2, 0, 0, 16, "boot info"),
                ("large info", 2, 0, 27, 16, "boot info"),
                ("short serial", 2, 0, 26, 15, "serial number"),
                ("large serial", 2, 0, 26, 17, "serial number"),
            ):
                with self.subTest(label=label):
                    source.write_text(f'''
.section .text,"ax",@progbits
.space {text_size}
.section .data,"aw",@progbits
.space {data_size}
.section .boot_info,"a",@progbits
.space {info_size}
.section .serial_number,"a",@progbits
.space {serial_size}
.section .shared_memory,"aw",@nobits
.space 2
''')
                    result = subprocess.run([
                        "avr-gcc", "-mmcu=atmega328p", "-nostartfiles", "-nostdlib",
                        "-Wl,-section-start=.data=0x800102",
                        str(source), f"-Wl,-T{ROOT / 'Bootloader/Bootloader_Custom.ld'}",
                        "-o", str(output)], capture_output=True, text=True)
                    if expected is None:
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(expected, result.stderr)
