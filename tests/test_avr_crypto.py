import os
import select
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from Tools.image_format import PAGE_SIZE, cmac_tag, crypt_image, derive_keys, load_device_key

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("avr-gcc") and shutil.which("qemu-system-avr"),
                     "AVR GCC and QEMU AVR are required")
class AvrCryptoTests(unittest.TestCase):
    def test_bootloader_cmac_and_ctr_match_package_tool(self):
        key_file = ROOT / ".local" / "device_key.hex"
        key_header = ROOT / "Bootloader" / "Release" / "device_key.h"
        if not key_file.exists() or not key_header.exists():
            self.skipTest("build the bootloader first")
        enc_key, mac_key = derive_keys(load_device_key(key_file))
        expected = (cmac_tag(mac_key, b"Iabcd") +
                    cmac_tag(mac_key, b"P" + b"\x00" * 40 + b"0123456789ab" +
                             b"\x00" * 16 + b"\x00\x00" + b"\x00" * PAGE_SIZE) +
                    crypt_image(enc_key, b"0123456789ab", b"\x00" * PAGE_SIZE)[:16])
        with tempfile.TemporaryDirectory() as folder:
            elf = Path(folder) / "crypto.elf"
            cmd = ["avr-gcc", "-mmcu=atmega328p", "-DF_CPU=16000000UL", "-DCBC=0",
                   "-DCTR=0", "-DECB=1", f"-I{ROOT / 'Common'}",
                   f"-I{ROOT / 'Bootloader/tiny-AES-c'}",
                   f"-I{ROOT / 'Bootloader/Release'}", "-Os", "-ffunction-sections",
                   "-fdata-sections", str(ROOT / "tests/avr_crypto_harness.c"),
                   str(ROOT / "Bootloader/tiny-AES-c/aes.c"),
                   str(ROOT / "Bootloader/crc.c"), "-Wl,--gc-sections,--relax", "-o", str(elf)]
            subprocess.run(cmd, check=True, capture_output=True)
            qemu = subprocess.Popen(
                ["qemu-system-avr", "-machine", "uno", "-bios", str(elf),
                 "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                bufsize=0,
            )
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
                qemu.stdin.close()
                qemu.stdout.close()
                qemu.stderr.close()


if __name__ == "__main__":
    unittest.main()
