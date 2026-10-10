"""Verify the emitted flash ABI and exercise the linker's overlap gates."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from intelhex import IntelHex

from Tools.Flasher.protocol import DeviceInfo, INFO_FORMAT
from Tools.image_format import HEADER_OFFSET, HEADER_SIZE, Header
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
''')
            result = subprocess.run(["avr-gcc", "-mmcu=atmega328p", f"-I{ROOT / 'Common'}",
                                     "-c", str(source), "-o", str(Path(directory) / "abi.o")],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

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
        self.assertEqual((info.sw_major, info.sw_minor, info.sw_revision, info.build), (1, 1, 0, 1))
        self.assertRegex(info.compile_date.rstrip(b"\0").decode(), r"^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{4}$")
        self.assertRegex(info.compile_time.rstrip(b"\0").decode(), r"^[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        self.assertEqual(bytes(boot.tobinarray(start=0x7ff0, size=16)), b"\xff" * 16)
        # The remainder of the serial's erase page has no loaded code or data.
        self.assertFalse(set(range(0x7f80, 0x7ff0)) & set(boot.addresses()))
        app = IntelHex(str(app_path))
        values = struct.unpack("<IHBBBH12s9s6sH12s16s",
                               bytes(app.tobinarray(start=HEADER_OFFSET, size=HEADER_SIZE)))
        header = Header(*values)
        self.assertEqual(header.version, "1.0.2+123")
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
