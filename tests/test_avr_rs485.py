"""Check the DE idle guard, continuous status burst, and response release."""

import os
from pathlib import Path
import select
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from Tools.Flasher.protocol import CMD_ACK, CMD_HEADER, CMD_INFO, CMD_NACK, INFO_FORMAT, encode

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("avr-gcc") and shutil.which("qemu-system-avr"),
                     "AVR GCC and QEMU AVR are required")
class AvrRs485Tests(unittest.TestCase):
    def test_guard_precedes_bytes_and_status_has_one_de_burst_with_valid_crc(self):
        if not (ROOT / "Bootloader/Release/device_key.h").exists():
            self.skipTest("build the bootloader first")
        info = struct.pack(INFO_FORMAT, 1, 1, 0, 1, b"Oct 11 2026", b"12:34:56",
                           b"\xff" * 16, 0xff, 0xff, 0xff, 0xff)
        expected = (encode(CMD_HEADER, bytes(68)) + encode(CMD_INFO, info) +
                    encode(CMD_HEADER, bytes(range(68))) + encode(CMD_INFO, info) +
                    encode(CMD_INFO, info) + encode(CMD_ACK, b"\xfe\xff") +
                    encode(CMD_NACK, b"\x03\0\x01") + b"\x01" * 6)
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "rs485.elf"
            result = subprocess.run([
                "avr-gcc", "-mmcu=atmega328p", "-DF_CPU=16000000UL",
                "-DCBC=0", "-DCTR=0", "-DECB=1", f"-I{ROOT / 'Common'}",
                f"-I{ROOT / 'Bootloader/tiny-AES-c'}", f"-I{ROOT / 'Bootloader/Release'}",
                "-Os", "-ffunction-sections", "-fdata-sections",
                str(ROOT / "tests/avr_rs485_harness.c"), str(ROOT / "Bootloader/crc.c"),
                "-Wl,--gc-sections,--relax", "-o", str(elf)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            qemu = subprocess.Popen([
                "qemu-system-avr", "-machine", "uno", "-bios", str(elf),
                "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            try:
                actual = bytearray()
                deadline = time.monotonic() + 3
                while len(actual) < len(expected) and time.monotonic() < deadline:
                    if select.select([qemu.stdout], [], [], 0.1)[0]:
                        actual.extend(os.read(qemu.stdout.fileno(), len(expected) - len(actual)))
                self.assertEqual(bytes(actual), expected)
            finally:
                qemu.terminate()
                qemu.wait(timeout=2)
                qemu.stdout.close()
                qemu.stderr.close()
