import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Tools" / "Flasher"))

try:
    from PyQt5.QtWidgets import QApplication
    from main import APP_BANNER, MyFlasherApp
except ImportError:
    QApplication = None

from Tools.image_format import build_package, parse_package, prepare_image
from Tools.Flasher.protocol import (CMD_ACK, CMD_BEGIN, CMD_FINISH, CMD_HEADER,
                                    CMD_NACK, CMD_PAGE, CMD_RESET, NACK_AUTH,
                                    NACK_PACKET, Packet, encode)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Tools.image_format import HEADER_FORMAT, HEADER_OFFSET, HEADER_SIZE, IMAGE_MAGIC, HW_ID
import struct
import tempfile

from cryptography.hazmat.primitives import serialization


class FakeSerial:
    def __init__(self):
        self.writes = []
        self.received = bytearray()

    def write(self, data):
        self.writes.append(data)

    @property
    def in_waiting(self):
        return len(self.received)

    def read(self, size):
        data = bytes(self.received[:size])
        del self.received[:size]
        return data

    def close(self):
        pass


@unittest.skipIf(QApplication is None, "PyQt5 is not installed")
class FlasherGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        raw = bytearray(b"\xff" * 390)
        raw[HEADER_OFFSET:HEADER_OFFSET + HEADER_SIZE] = struct.pack(
            HEADER_FORMAT, IMAGE_MAGIC, HW_ID, 1, 0, 2, 122, 0,
            b"Sep 28 2026\0", b"12:34:56\0", b"5.4.0\0",
            b"\x00" * 12, b"\x00" * 16)
        root = bytes(range(16))
        image, header = prepare_image(bytes(raw), root, b"0123456789ab")
        signer = Ed25519PrivateKey.generate()
        self.package = build_package(image, header, root, signer)
        self.header, self.pages = parse_package(self.package, signer.public_key())
        self.signer = signer
        self.window = MyFlasherApp()
        self.fake = FakeSerial()
        self.window.serial_port = self.fake
        self.window.bootloader_active = True
        self.window.file_header = self.header
        self.window.pages = self.pages
        self.window.update_flash_button()

    def tearDown(self):
        self.window.close()

    def test_retry_duplicate_ack_and_finish(self):
        self.window.start_flash()
        self.assertEqual(self.fake.writes[-1][1], CMD_BEGIN)
        self.window.handle_packet(Packet(CMD_ACK, b"\xff\xff"))
        self.assertEqual(self.fake.writes[-1][1], CMD_PAGE)
        first = self.fake.writes[-1]
        self.window.handle_packet(Packet(CMD_NACK, b"\x00\x00" + bytes((NACK_PACKET,))))
        self.assertEqual(self.fake.writes[-1], first)
        self.window.handle_packet(Packet(CMD_ACK, b"\x00\x00"))
        self.assertEqual(self.window.page_index, 1)
        count = len(self.fake.writes)
        self.window.handle_packet(Packet(CMD_ACK, b"\x00\x00"))
        self.assertEqual(len(self.fake.writes), count)
        for index in range(1, len(self.pages)):
            self.window.handle_packet(Packet(CMD_ACK, index.to_bytes(2, "little")))
        self.assertEqual(self.fake.writes[-1][1], CMD_FINISH)
        self.window.handle_packet(Packet(CMD_ACK, len(self.pages).to_bytes(2, "little")))
        self.assertFalse(self.window.flashing)

    def test_auth_nack_stops_transfer(self):
        self.window.start_flash()
        self.window.handle_packet(Packet(CMD_ACK, b"\xff\xff"))
        self.window.handle_packet(Packet(CMD_NACK, b"\x00\x00" + bytes((NACK_AUTH,))))
        self.assertFalse(self.window.flashing)
        self.assertIsNone(self.window.pending)

    def test_trusted_key_selection_and_firmware_revalidation(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            package_path = directory / "firmware.bin"
            public_path = directory / "signing_public.pem"
            wrong_path = directory / "wrong_public.pem"
            package_path.write_bytes(self.package)
            public_path.write_bytes(self.signer.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
            wrong_path.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))

            self.window.ui.ln_img.setText(str(package_path))
            self.assertTrue(self.window.set_trusted_key(public_path))
            self.assertEqual(self.window.file_header.to_bytes(), self.header.to_bytes())
            self.assertTrue(self.window.ui.btn_flash.isEnabled())

            self.assertTrue(self.window.set_trusted_key(wrong_path))
            self.assertIsNone(self.window.file_header)
            self.assertFalse(self.window.ui.btn_flash.isEnabled())

    def test_non_ed25519_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "not-a-key.pem"
            key_path.write_text("not a PEM key")
            original = self.window.trusted_key_path
            self.assertFalse(self.window.set_trusted_key(key_path))
            self.assertEqual(self.window.trusted_key_path, original)
            self.assertTrue(self.window.ui.btn_key.isEnabled())

    def test_go_bootloader_waits_for_header(self):
        self.window.bootloader_active = False
        self.window.update_flash_button()
        self.window.ui.btn_bootloader.click()
        self.assertEqual(self.fake.writes[-1], b"BOOT\n")
        self.assertEqual(self.window.mode_pending, "boot")
        self.assertFalse(self.window.bootloader_active)
        self.assertFalse(self.window.ui.btn_flash.isEnabled())
        packet = encode(CMD_HEADER, b"\x00" * HEADER_SIZE)
        self.fake.received.extend(packet[:10])
        self.window.poll_serial()
        self.assertEqual(self.window.mode_pending, "boot")
        self.fake.received.extend(packet[10:])
        self.window.poll_serial()
        self.assertIsNone(self.window.mode_pending)
        self.assertTrue(self.window.bootloader_active)

    def test_go_application_waits_for_banner(self):
        self.window.ui.btn_app.click()
        self.assertEqual(self.fake.writes[-1], encode(CMD_RESET))
        self.assertEqual(self.window.mode_pending, "app")
        self.assertTrue(self.window.bootloader_active)
        self.assertFalse(self.window.ui.btn_flash.isEnabled())
        self.fake.received.extend(APP_BANNER[:5])
        self.window.poll_serial()
        self.assertEqual(self.window.mode_pending, "app")
        self.fake.received.extend(APP_BANNER[5:])
        self.window.poll_serial()
        self.assertIsNone(self.window.mode_pending)
        self.assertTrue(self.window.app_active)
        self.assertFalse(self.window.bootloader_active)
        self.assertFalse(self.window.ui.btn_app.isEnabled())

    def test_go_application_reports_unconfirmed_transition(self):
        self.window.ui.btn_app.click()
        self.fake.received.extend(encode(CMD_HEADER, b"\x00" * HEADER_SIZE))
        self.window.poll_serial()
        self.assertEqual(self.window.mode_pending, "app")
        self.window.mode_deadline = 0
        self.window.poll_serial()
        self.assertIsNone(self.window.mode_pending)
        self.assertTrue(self.window.bootloader_active)
        self.assertIn("App transition not confirmed", self.window.ui.tx_log.toPlainText())


if __name__ == "__main__":
    unittest.main()
