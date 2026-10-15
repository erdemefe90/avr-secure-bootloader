import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Tools" / "Flasher"))

try:
    from PyQt5.QtWidgets import QApplication
    from main import MyFlasherApp
except ImportError:
    QApplication = None

from Tools.image_format import build_package, parse_package, prepare_image
from Tools.Flasher.protocol import (CMD_ACK, CMD_BEGIN, CMD_FINISH, CMD_HEADER,
                                    CMD_NACK, CMD_PAGE, CMD_RESET, NACK_AUTH,
                                    NACK_PACKET, Packet, encode)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Tools.image_format import HEADER_FORMAT, HEADER_OFFSET, HEADER_SIZE, IMAGE_MAGIC
import struct
import tempfile
from dataclasses import replace
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from Tools.Flasher.protocol import CMD_INFO, CMD_LOCK, CONTROL_SEQ, INFO_FORMAT, DeviceInfo, encode_serial


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
            HEADER_FORMAT, IMAGE_MAGIC, 3, 1, 1, 0, 2, 122,
            b"Sep 28 2026\0", b"12:34:56\0", b"5.4.0\0", 0,
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
        self.info_raw = struct.pack(INFO_FORMAT, 1, 1, 0, 1,
                                    b"Oct  2 2026\0", b"12:34:56\0", encode_serial("SN-001"),
                                    0xff, 0xd8, 0xfd, 0xff)
        self.window.device_info = DeviceInfo.from_bytes(self.info_raw)
        self.window.file_header = self.header
        self.window.pages = self.pages
        self.window.update_flash_button()

    def tearDown(self):
        self.window.close()

    def test_hardware_version_is_major_minor_in_both_panels(self):
        self.window.show_header(self.header, file=True)
        self.window.show_header(self.header, file=False)
        self.assertEqual(self.window.ui.lb_file_hw.text(), "3.1")
        self.assertEqual(self.window.ui.lb_dev_hw.text(), "3.1")

    def test_hardware_mismatch_warns_before_begin_and_can_be_cancelled_or_accepted(self):
        from main import QMessageBox
        for field in ("hw_major", "hw_minor"):
            with self.subTest(field=field):
                self.fake.writes.clear()
                device = replace(self.header, build=self.header.build - 1,
                                 **{field: getattr(self.header, field) + 1})
                self.window.handle_packet(Packet(CMD_HEADER, device.to_bytes()))
                self.assertEqual(self.window.device_header.hardware_version, device.hardware_version)
                self.assertTrue(self.window.ui.btn_flash.isEnabled())
                with patch("main.QMessageBox.warning", return_value=QMessageBox.No) as popup:
                    self.window.start_flash()
                self.assertEqual(self.fake.writes, [])
                self.assertFalse(self.window.flashing)
                self.assertIsNone(self.window.pending)
                self.assertIn(self.header.hardware_version, popup.call_args.args[2])
                self.assertIn(device.hardware_version, popup.call_args.args[2])
                self.assertEqual(popup.call_args.args[4], QMessageBox.No)
                with patch("main.QMessageBox.warning", return_value=QMessageBox.Yes):
                    self.window.start_flash()
                self.assertEqual(self.fake.writes[-1][1], CMD_BEGIN)
                self.window.fail_flash("Test transfer stopped")

    def test_matching_or_unknown_hardware_needs_no_popup(self):
        for device in (None, replace(self.header, build=self.header.build - 1)):
            with self.subTest(device=device):
                self.window.device_header = device
                self.window.update_flash_button()
                with patch("main.QMessageBox.warning") as popup:
                    self.window.start_flash()
                popup.assert_not_called()
                self.assertEqual(self.fake.writes[-1][1], CMD_BEGIN)
                self.window.fail_flash("Test transfer stopped")

    def test_force_keeps_hardware_warning_and_popup_rechecks_device_permissions(self):
        from main import QMessageBox
        self.window.device_header = replace(self.header, hw_major=255)
        self.window.ui.radioButton.setChecked(True)
        self.window.update_flash_button()
        def lose_write_permission(*args):
            self.window.device_info = replace(self.window.device_info, lock_bits=0xfb)
            self.window.update_flash_button()
            return QMessageBox.Yes
        with patch("main.QMessageBox.warning", side_effect=lose_write_permission) as popup:
            self.window.start_flash()
        popup.assert_called_once()
        self.assertFalse(self.window.flashing)
        self.assertEqual(self.fake.writes, [])

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

    def test_go_application_sends_reset_without_confirmation(self):
        self.window.device_header = self.header
        self.window.ui.btn_app.click()
        self.assertEqual(self.fake.writes[-1], encode(CMD_RESET))
        self.assertIsNone(self.window.mode_pending)
        self.assertFalse(self.window.bootloader_active)
        self.assertIsNone(self.window.device_header)
        self.assertIsNone(self.window.device_info)
        self.assertFalse(self.window.ui.btn_flash.isEnabled())
        self.assertFalse(self.window.ui.btn_app.isEnabled())
        self.window.mode_deadline = 0
        self.window.poll_serial()  # no application output
        log = self.window.ui.tx_log.toPlainText()
        self.assertIn("Application start requested", log)
        self.assertNotIn("transition not confirmed", log)

    def test_bootloader_header_after_reset_remains_detectable(self):
        self.window.ui.btn_app.click()
        self.fake.received.extend(encode(CMD_HEADER, b"\x00" * HEADER_SIZE))
        self.window.poll_serial()
        self.assertIsNone(self.window.mode_pending)
        self.assertTrue(self.window.bootloader_active)
        self.assertNotIn("App transition not confirmed", self.window.ui.tx_log.toPlainText())

    def test_info_displays_boot_metadata_serial_fuses_and_locks(self):
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw))
        self.assertEqual(self.window.ui.lb_boot_version.text(), "1.1.0+1")
        self.assertEqual(self.window.ui.lb_boot_compiled.text(), "Oct  2 2026 12:34:56")
        self.assertEqual(self.window.ui.lb_serial.text(), "SN-001")
        self.assertIn("High: 0xD8", self.window.ui.lb_fuses.text())
        self.assertIn("App writes: enabled", self.window.ui.lb_blb0.text())
        self.assertTrue(self.window.ui.btn_flash.isEnabled())
        # A truncated status packet cannot replace a valid status.
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw[:-1]))
        self.assertEqual(self.window.device_info.serial_text, "SN-001")

    def test_force_cannot_bypass_hardware_lock_or_missing_info(self):
        self.window.ui.radioButton.setChecked(True)
        for lock_bits in (0xfb, 0xf7):
            self.window.device_info = replace(DeviceInfo.from_bytes(self.info_raw), lock_bits=lock_bits)
            self.window.update_flash_button()
            self.assertFalse(self.window.ui.btn_flash.isEnabled())
        self.window.device_info = None
        self.window.update_flash_button()
        self.assertFalse(self.window.ui.btn_flash.isEnabled())

    def test_lock_confirmation_retry_and_readback(self):
        self.window.ui.cb_lb.setCurrentIndex(self.window.ui.cb_lb.findData(2))
        from main import QMessageBox
        with patch("main.QMessageBox.warning", return_value=QMessageBox.No):
            self.window.lock_flash()
        self.assertEqual(self.fake.writes, [])
        with patch("main.QMessageBox.warning", return_value=QMessageBox.Yes):
            self.window.lock_flash()
        request = encode(CMD_LOCK, b"\x01")
        self.assertEqual(self.fake.writes[-1], request)
        self.assertFalse(self.window.ui.btn_flash.isEnabled())
        self.assertFalse(self.window.ui.btn_app.isEnabled())
        self.window.pending["deadline"] = 0
        self.window.poll_serial()
        self.assertEqual(self.fake.writes[-1], request)
        self.window.handle_packet(Packet(CMD_ACK, CONTROL_SEQ.to_bytes(2, "little")))
        self.assertEqual(self.fake.writes[-1], encode(CMD_INFO))
        self.assertIsNone(self.window.device_info)
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw[:-1] + b"\xfe"))
        self.assertIsNone(self.window.pending)
        self.assertIn("Mode 2", self.window.ui.lb_isp.text())
        self.assertEqual(self.window.ui.cb_lb.currentData(), 2)
        self.assertFalse(self.window.ui.btn_lock.isEnabled())
        self.assertTrue(self.window.ui.btn_flash.isEnabled())

    def test_info_read_timeout_and_disconnect_clear_status(self):
        self.window.read_device_info()
        self.assertEqual(self.fake.writes[-1], encode(CMD_INFO))
        self.assertIsNone(self.window.device_info)
        self.window.pending["attempts"] = 5
        self.window.pending["deadline"] = 0
        self.window.poll_serial()
        self.assertIsNone(self.window.pending)
        self.assertFalse(self.window.ui.btn_flash.isEnabled())
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw))
        self.assertTrue(self.window.ui.btn_flash.isEnabled())
        self.window.connect_serial()
        self.assertIsNone(self.window.device_info)
        self.assertEqual(self.window.ui.lb_fuses.text(), "—")

    def test_info_refresh_syncs_lb_and_keeps_all_lock_displays(self):
        combo = self.window.ui.cb_lb
        for locks in range(64):
            with self.subTest(locks=locks):
                combo.setCurrentIndex(combo.findData(3))
                self.window.ui.btn_info.click()
                self.assertEqual(self.fake.writes[-1], encode(CMD_INFO))
                self.assertIsNone(self.window.device_info)
                self.window.handle_packet(Packet(CMD_INFO, b"\x00"))
                self.assertEqual(combo.currentData(), 3)
                self.assertIsNotNone(self.window.pending)
                writes = len(self.fake.writes)
                raw = self.info_raw[:-1] + bytes((0xc0 | locks,))
                self.window.handle_packet(Packet(CMD_INFO, raw))
                info = DeviceInfo.from_bytes(raw)
                self.assertEqual(combo.currentData(), info.lb_mode)
                self.assertIn(f"Mode {info.blb0_mode}", self.window.ui.lb_blb0.text())
                self.assertIn(f"Mode {info.blb1_mode}", self.window.ui.lb_blb1.text())
                self.assertIsNone(self.window.pending)
                self.assertFalse(self.window.ui.btn_lock.isEnabled())
                self.assertEqual(len(self.fake.writes), writes)

    def test_initial_info_syncs_lb_but_periodic_info_preserves_user_choice(self):
        self.window.device_info = None
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw))
        combo = self.window.ui.cb_lb
        self.assertEqual(combo.currentData(), 1)
        combo.setCurrentIndex(combo.findData(3))
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw))
        self.assertEqual(combo.currentData(), 3)
        self.assertTrue(self.window.ui.btn_lock.isEnabled())
        self.assertEqual(self.fake.writes, [])

    def test_status_controls_disabled_during_flash(self):
        self.window.start_flash()
        self.assertFalse(self.window.ui.btn_info.isEnabled())
        self.assertFalse(self.window.ui.btn_lock.isEnabled())
        self.assertFalse(self.window.ui.cb_lb.isEnabled())

    def test_boot_info_and_lock_controls_are_on_separate_tabs(self):
        self.assertTrue(self.window.ui.tab_boot.isAncestorOf(self.window.ui.lb_serial))
        self.assertTrue(self.window.ui.tab_boot.isAncestorOf(self.window.ui.lb_boot_version))
        self.assertTrue(self.window.ui.tab_protection.isAncestorOf(self.window.ui.lb_blb0))
        self.assertTrue(self.window.ui.tab_protection.isAncestorOf(self.window.ui.lb_blb1))
        self.assertTrue(self.window.ui.tab_protection.isAncestorOf(self.window.ui.lb_isp))
        self.assertTrue(self.window.ui.tab_protection.isAncestorOf(self.window.ui.btn_lock))

    def test_only_lb_is_editable_and_isp_protection_keeps_updates(self):
        self.assertFalse(hasattr(self.window.ui, "cb_blb0"))
        self.assertFalse(hasattr(self.window.ui, "cb_blb1"))
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw[:-1] + b"\xfc"))
        self.assertIn("Mode 1", self.window.ui.lb_blb0.text())
        self.assertIn("Mode 1", self.window.ui.lb_blb1.text())
        self.assertIn("Mode 3", self.window.ui.lb_isp.text())
        self.assertIn("LB2=0, LB1=0", self.window.ui.lb_isp.text())
        self.assertTrue(self.window.ui.btn_flash.isEnabled())

    def test_existing_blb_read_locks_still_block_flash_but_not_lb_programming(self):
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw[:-1] + b"\xf3"))
        self.assertIn("Mode 3", self.window.ui.lb_blb0.text())
        self.assertFalse(self.window.ui.btn_flash.isEnabled())
        self.window.ui.cb_lb.setCurrentIndex(self.window.ui.cb_lb.findData(2))
        self.assertTrue(self.window.ui.btn_lock.isEnabled())
        from main import QMessageBox
        with patch("main.QMessageBox.warning", return_value=QMessageBox.Yes):
            self.window.lock_flash()
        self.assertEqual(self.fake.writes[-1], encode(CMD_LOCK, b"\x01"))

    def test_lb_targets_have_effect_confirmation_and_preserve_blb_readback(self):
        combo = self.window.ui.cb_lb
        self.assertEqual([combo.itemData(i) for i in range(combo.count())], [None, 1, 2, 3])
        combo.setCurrentIndex(combo.findData(3))
        from main import QMessageBox
        with patch("main.QMessageBox.warning", return_value=QMessageBox.Yes) as confirmation:
            self.window.lock_flash()
        self.assertIn("ISP flash / EEPROM", confirmation.call_args.args[2])
        self.assertEqual(self.fake.writes[-1], encode(CMD_LOCK, b"\x03"))
        self.window.handle_packet(Packet(CMD_ACK, CONTROL_SEQ.to_bytes(2, "little")))
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw[:-1] + b"\xfc"))
        self.assertIn("Hardware lock modes verified", self.window.ui.tx_log.toPlainText())
        self.assertTrue(self.window.ui.btn_flash.isEnabled())
        self.assertIn("Mode 1", self.window.ui.lb_blb0.text())
        self.assertIn("Mode 1", self.window.ui.lb_blb1.text())
        self.assertEqual(combo.currentData(), 3)

    def test_lb_only_lock_keeps_updates_and_reports_failed_readback(self):
        self.window.ui.cb_lb.setCurrentIndex(self.window.ui.cb_lb.findData(2))
        from main import QMessageBox
        with patch("main.QMessageBox.warning", return_value=QMessageBox.Yes):
            self.window.lock_flash()
        self.assertEqual(self.fake.writes[-1], encode(CMD_LOCK, b"\x01"))
        self.window.handle_packet(Packet(CMD_ACK, CONTROL_SEQ.to_bytes(2, "little")))
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw))
        self.assertIn("readback did not match", self.window.ui.tx_log.toPlainText())
        self.assertNotIn("Hardware lock modes verified", self.window.ui.tx_log.toPlainText())
        self.window.handle_packet(Packet(CMD_INFO, self.info_raw[:-1] + b"\xfe"))
        self.assertTrue(self.window.ui.btn_flash.isEnabled())
        self.assertIn("Mode 2", self.window.ui.lb_isp.text())
        self.window.ui.cb_lb.setCurrentIndex(self.window.ui.cb_lb.findData(1))
        self.assertFalse(self.window.ui.btn_lock.isEnabled())
        self.assertIn("chip erase", self.window.ui.btn_lock.toolTip())

    def test_example_or_arbitrary_application_text_is_not_mode_detection(self):
        self.window.handle_packet(Packet(CMD_HEADER, self.header.to_bytes()))
        original_info = self.window.device_info
        for data in (b"Hello World!!\r\n", b"my application started\n"):
            self.fake.received.extend(data)
            self.window.poll_serial()
            self.assertTrue(self.window.bootloader_active)
            self.assertEqual(self.window.device_header.to_bytes(), self.header.to_bytes())
            self.assertEqual(self.window.device_info, original_info)
        self.assertNotIn("Application detected", self.window.ui.tx_log.toPlainText())

    def test_serial_status_payload_is_displayed_as_bytes(self):
        sample = encode_serial("short-ID")
        raw = self.info_raw[:26] + sample + self.info_raw[-4:]
        framed = encode(CMD_INFO, raw)
        self.fake.received.extend(framed[:38])
        self.window.poll_serial()
        self.fake.received.extend(framed[38:])
        self.window.poll_serial()
        self.assertTrue(self.window.bootloader_active)
        self.assertEqual(self.window.device_info.serial, sample)
        self.assertEqual(self.window.ui.lb_serial.text(), "short-ID")

    def test_serial_display_is_plain_text_and_handles_invalid_or_erased_flash(self):
        from PyQt5.QtCore import Qt
        for raw, expected in ((encode_serial("<b>SN</b>"), "<b>SN</b>"),
                              (encode_serial("ç-123"), "ç-123"),
                              (b"\xff" * 16, "Not provisioned"),
                              (b"A" * 16, "Invalid serial format")):
            with self.subTest(raw=raw):
                self.window.handle_packet(Packet(CMD_INFO, self.info_raw[:26] + raw + self.info_raw[-4:]))
                self.assertEqual(self.window.ui.lb_serial.text(), expected)
                self.assertEqual(self.window.ui.lb_serial.textFormat(), Qt.PlainText)



    def test_icons_load_when_launched_from_other_unicode_directory(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory(prefix="avr-ç-") as directory:
            os.chdir(directory)
            try:
                window = MyFlasherApp()
                try:
                    self.assertFalse(window.windowIcon().isNull())
                    self.assertFalse(window.ui.btn_key.icon().isNull())
                    self.assertFalse(window.ui.btn_img.icon().isNull())
                finally:
                    window.close()
            finally:
                os.chdir(original)

    def test_windows_app_identity_is_set_before_qt_application_creation(self):
        import ctypes
        from main import create_gui_application, WINDOWS_APP_ID
        order = []
        shell = Mock()
        shell.SetCurrentProcessExplicitAppUserModelID.side_effect = lambda value: order.append("app-id") or 0
        application = Mock()
        with patch("main.sys.platform", "win32"), patch("ctypes.WinDLL", return_value=shell, create=True), patch(
                "main.QApplication", side_effect=lambda argv: order.append("qt") or application):
            self.assertIs(create_gui_application([]), application)
        self.assertEqual(order, ["app-id", "qt"])
        shell.SetCurrentProcessExplicitAppUserModelID.assert_called_once_with(WINDOWS_APP_ID)
        self.assertEqual(shell.SetCurrentProcessExplicitAppUserModelID.argtypes, [ctypes.c_wchar_p])
        application.setApplicationName.assert_called_once_with("AVR Secure Flasher")
        self.assertFalse(application.setWindowIcon.call_args.args[0].isNull())


if __name__ == "__main__":
    unittest.main()
