"""Signed AVR firmware flasher. Run with a trusted, pinned Ed25519 public key."""

import html
import os
import sys
import time
from pathlib import Path

# With a command, run the headless CLI before loading any Qt modules.
if __name__ == "__main__" and len(sys.argv) > 1:
    if __package__:
        from .cli import main as cli_main
    else:
        from cli import main as cli_main
    raise SystemExit(cli_main())

import serial
import serial.tools.list_ports
import PyQt5
from PyQt5.QtCore import QCoreApplication, QTimer
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if sys.platform == "win32":
    # Qt 5 may decode its installed plugin path incorrectly under Unicode Windows paths.
    plugin_dir = Path(PyQt5.__file__).resolve().parent / "Qt5" / "plugins"
    if plugin_dir.is_dir():
        QCoreApplication.setLibraryPaths([str(plugin_dir)])

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from image_format import HEADER_SIZE, Header, load_verifier
from policy import verified_package, flash_block_reason, hardware_warning, version_tuple as firmware_version
from Flasher_GUI import Ui_Dialog
from protocol import (CMD_ACK, CMD_BEGIN, CMD_FINISH, CMD_HEADER, CMD_NACK,
                      CMD_PAGE, CMD_RESET, CMD_INFO, CMD_LOCK, CONTROL_SEQ,
                      DeviceInfo, LB_MODE_LABELS, lock_mode_mask, lock_mode_summary,
                      NACK_PACKET, Parser, encode)

RETRIES = 5
PACKET_TIMEOUT = 2.0
FINISH_TIMEOUT = 8.0
MODE_TIMEOUT = 4.0
GUI_DIRECTORY = Path(__file__).resolve().parent
WINDOWS_APP_ID = "AVRSecureBootloader.Flasher"


def create_gui_application(argv):
    if sys.platform == "win32":
        import ctypes
        set_app_id = ctypes.WinDLL("shell32").SetCurrentProcessExplicitAppUserModelID
        set_app_id.argtypes = [ctypes.c_wchar_p]
        set_app_id.restype = ctypes.c_long
        result = set_app_id(WINDOWS_APP_ID)
        if result != 0:
            print(f"Windows taskbar application ID failed: HRESULT 0x{result & 0xffffffff:08X}",
                  file=sys.stderr)
    app = QApplication(argv)
    app.setApplicationName("AVR Secure Flasher")
    app.setWindowIcon(QIcon(str(GUI_DIRECTORY / "avr.png")))
    return app


class MyFlasherApp(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.setWindowTitle("AVR Secure Flasher")
        self.setWindowIcon(QIcon(str(GUI_DIRECTORY / "avr.png")))
        folder_icon = QIcon(str(GUI_DIRECTORY / "folder.png"))
        self.ui.btn_key.setIcon(folder_icon)
        self.ui.btn_img.setIcon(folder_icon)
        self.serial_port = None
        self.parser = Parser()
        self.file_header = None
        self.device_header = None
        self.device_info = None
        self.pages = None
        self.bootloader_active = False
        self.mode_pending = None
        self.mode_deadline = 0.0
        self.flashing = False
        self.page_index = 0
        self.pending = None

        default_key = Path(__file__).resolve().parents[2] / ".local" / "signing_public.pem"
        self.trusted_key_path = Path(os.environ.get("AVR_TRUSTED_PUBLIC_KEY", default_key))
        self.ui.ln_key.setText(str(self.trusted_key_path))
        self.ui.ln_key.setReadOnly(True)
        self.ui.label_2.setText("Trusted key")
        self.ui.radioButton.setText("Force")
        self.ui.radioButton.toggled.connect(self.update_flash_button)
        self.ui.btn_connect.clicked.connect(self.connect_serial)
        self.ui.btn_key.clicked.connect(self.select_key)
        self.ui.btn_bootloader.clicked.connect(self.go_bootloader)
        self.ui.btn_app.clicked.connect(self.reset_device)
        self.ui.btn_img.clicked.connect(self.select_image)
        self.ui.btn_flash.clicked.connect(self.start_flash)
        self.ui.btn_info.clicked.connect(self.read_device_info)
        self.ui.btn_lock.clicked.connect(self.lock_flash)
        self.ui.cb_lb.addItem("Keep current mode", None)
        for mode, text in LB_MODE_LABELS.items():
            self.ui.cb_lb.addItem(f"Mode {mode} — {text}", mode)
        self.ui.cb_lb.currentIndexChanged.connect(self.update_flash_button)
        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(self.poll_serial)
        self.poll_timer.start(25)
        self.ports_timer = QTimer(self)
        self.ports_timer.timeout.connect(self.refresh_ports)
        self.ports_timer.start(2000)
        self.refresh_ports()
        self.show_header(None, file=True)
        self.show_header(None, file=False)
        self.show_device_info()
        self.update_flash_button()

    def log(self, message: str, error: bool = False):
        color = "red" if error else "black"
        self.ui.tx_log.append(f'<span style="color:{color}">{html.escape(message)}</span>')

    @staticmethod
    def version_tuple(header: Header):
        return firmware_version(header)

    def show_header(self, header: Header | None, file: bool):
        prefix = "file" if file else "dev"
        values = {
            "sw": header.version if header else "—",
            "hw": header.hardware_version if header else "—",
            "compiler": header.compiler if header else "—",
            "compile_time": header.compiled if header else "—",
            "auth": "Signed" if file and header else "CMAC" if header else "—",
            "size": f"{header.image_size} bytes" if header else "—",
        }
        for name, value in values.items():
            getattr(self.ui, f"lb_{prefix}_{name}").setText(value)

    def update_flash_button(self):
        reason = (flash_block_reason(self.file_header, self.device_header, self.device_info,
                                    self.ui.radioButton.isChecked()) if self.file_header else None)
        enabled = (self.serial_port is not None and self.bootloader_active and
                   self.file_header is not None and not self.flashing and
                   self.mode_pending is None and self.pending is None and reason is None and
                   self.device_info is not None and self.device_info.application_writable and
                   self.device_info.application_readable)
        self.ui.btn_flash.setEnabled(enabled)
        self.ui.btn_flash.setToolTip(reason or "")
        self.ui.btn_bootloader.setEnabled(self.serial_port is not None and
                                          self.mode_pending is None and not self.flashing and self.pending is None)
        self.ui.btn_app.setEnabled(self.serial_port is not None and self.bootloader_active and
                                   self.mode_pending is None and not self.flashing and self.pending is None)
        self.ui.btn_key.setEnabled(not self.flashing)
        self.ui.btn_img.setEnabled(not self.flashing)
        idle = (self.serial_port is not None and self.bootloader_active and
                self.mode_pending is None and not self.flashing and self.pending is None)
        self.ui.btn_info.setEnabled(idle)
        self.ui.cb_lb.setEnabled(idle)
        mask = 0
        try:
            if self.device_info:
                mask = lock_mode_mask(self.device_info, self.ui.cb_lb.currentData())
            self.ui.btn_lock.setToolTip("")
        except ValueError as exc:
            self.ui.btn_lock.setToolTip(str(exc))
        self.ui.btn_lock.setEnabled(bool(idle and mask))

    def show_device_info(self):
        info = self.device_info
        self.ui.lb_boot_version.setText(
            f"{info.sw_major}.{info.sw_minor}.{info.sw_revision}+{info.build}" if info else "—")
        self.ui.lb_boot_compiled.setText(
            f"{Header._text(info.compile_date)} {Header._text(info.compile_time)}" if info else "—")
        self.ui.lb_serial.setText(
            "Not provisioned" if info and info.serial == b"\xff" * 16 else
            (info.serial_text or "Invalid serial format") if info else "—")
        self.ui.lb_fuses.setText(
            f"Low: 0x{info.low_fuse:02X}   High: 0x{info.high_fuse:02X}   "
            f"Extended: 0x{info.extended_fuse:02X}" if info else "—")
        if info:
            self.ui.lb_locks.setText(f"0x{info.lock_bits:02X} (0 = programmed / locked)")
            descriptions = info.lock_descriptions()
            self.ui.lb_blb0.setText(descriptions["blb0"])
            self.ui.lb_blb1.setText(descriptions["blb1"])
            self.ui.lb_isp.setText(descriptions["lb"])
            issues = []
            if info.high_fuse & 7:
                issues.append("BOOTRST / BOOTSZ require ISP correction")
            if not info.application_readable:
                issues.append("Bootloader cannot read application for CMAC")
            if not info.lock_bits & 0x20:
                issues.append("App cannot read boot metadata")
            if info.lb_mode is None:
                issues.append("Reserved LB2/LB1 combination; only LB Mode 3 can repair it without erase")
            self.ui.lb_fuse_note.setText("; ".join(issues) or "Boot section fuse configuration OK")
        else:
            for name in ("lb_locks", "lb_blb0", "lb_blb1", "lb_isp", "lb_fuse_note"):
                getattr(self.ui, name).setText("—")

    def read_device_info(self):
        if not self.ui.btn_info.isEnabled():
            return
        self.device_info = None
        self.show_device_info()
        self.send_request(CMD_INFO, b"", CONTROL_SEQ, "info")
        self.update_flash_button()

    def sync_lock_targets(self, info):
        combo = self.ui.cb_lb
        blocked = combo.blockSignals(True)
        combo.setCurrentIndex(combo.findData(info.lb_mode))
        combo.blockSignals(blocked)

    def lock_flash(self):
        if not self.ui.btn_lock.isEnabled():
            return
        target = self.ui.cb_lb.currentData()
        mask = lock_mode_mask(self.device_info, target)
        expected = self.device_info.lock_bits & ~mask & 0x3f
        description = lock_mode_summary(self.device_info, target)
        answer = QMessageBox.warning(
            self, "Permanent hardware lock bits",
            f"{description}?\n\n"
            "Unlocking requires an ISP chip erase, which erases the bootloader, "
            "application and serial number. These bits can only change from 1 to 0. "
            "LB protection alone does not stop bootloader SPM updates.\n\nApply these modes?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self.device_info = None
        self.show_device_info()
        self.send_request(CMD_LOCK, bytes((mask,)), CONTROL_SEQ, "lock", expected_locks=expected)
        self.update_flash_button()

    def refresh_ports(self):
        if self.serial_port:
            return
        selected = self.ui.cb_port.currentData()
        self.ui.cb_port.clear()
        for port in serial.tools.list_ports.comports():
            self.ui.cb_port.addItem(f"{port.device} - {port.description}", port.device)
        if selected:
            index = self.ui.cb_port.findData(selected)
            if index >= 0:
                self.ui.cb_port.setCurrentIndex(index)

    def connect_serial(self):
        if self.serial_port:
            self.serial_port.close()
            self.serial_port = None
            self.bootloader_active = False
            self.mode_pending = None
            self.device_header = None
            self.device_info = None
            self.show_device_info()
            self.pending = None
            self.flashing = False
            self.show_header(None, file=False)
            self.ui.btn_connect.setText("Connect")
            self.update_flash_button()
            self.log("Disconnected")
            return
        port = self.ui.cb_port.currentData()
        if not port:
            self.log("Select a serial port", error=True)
            return
        try:
            self.serial_port = serial.Serial(port, 115200, timeout=0, write_timeout=0.5)
        except (serial.SerialException, OSError) as exc:
            self.log(f"Connection failed: {exc}", error=True)
            return
        self.parser = Parser()
        self.bootloader_active = False
        self.mode_pending = None
        self.device_header = None
        self.device_info = None
        self.show_device_info()
        self.show_header(None, file=False)
        self.ui.btn_connect.setText("Disconnect")
        self.log(f"Connected to {port}")
        self.update_flash_button()

    def verify_image(self, path: Path):
        self.file_header = None
        self.pages = None
        self.show_header(None, file=True)
        self.update_flash_button()
        try:
            header, pages = verified_package(path, self.trusted_key_path)
        except (OSError, ValueError, TypeError) as exc:
            self.log(f"Firmware rejected: {exc}", error=True)
            return False
        self.file_header = header
        self.pages = pages
        self.show_header(header, file=True)
        self.log(f"Signature verified: {header.version}, {header.image_size} bytes")
        self.update_flash_button()
        if (self.device_header and self.version_tuple(header) <= self.version_tuple(self.device_header)
                and not self.ui.radioButton.isChecked()):
            self.log("Flash locked: selected version is not newer. Force can override the version rule.")
        return True

    def select_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select signed firmware", "", "Firmware (*.bin)")
        if not path:
            return
        self.ui.ln_img.setText(path)
        self.verify_image(Path(path))

    def set_trusted_key(self, path: Path):
        try:
            verifier = load_verifier(path)
            if not isinstance(verifier, Ed25519PublicKey):
                raise ValueError("selected file is not an Ed25519 public key")
        except (OSError, ValueError, TypeError) as exc:
            self.log(f"Trusted key rejected: {exc}", error=True)
            return False

        self.trusted_key_path = path
        self.ui.ln_key.setText(str(path))
        self.log(f"Trusted key selected: {path}")

        image_path = Path(self.ui.ln_img.text()) if self.ui.ln_img.text() else None
        if image_path:
            self.log("Revalidating selected firmware with the new trusted key")
            self.verify_image(image_path)
        return True

    def select_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select trusted Ed25519 public key", str(self.trusted_key_path.parent),
            "PEM public keys (*.pem);;All files (*)")
        if path:
            self.set_trusted_key(Path(path))

    def go_bootloader(self):
        if not self.serial_port:
            self.log("Connect to the device first", error=True)
            return
        if self.flashing or self.mode_pending or self.pending:
            return
        if self.bootloader_active:
            self.log("Bootloader is already active")
            return
        try:
            self.serial_port.write(b"BOOT\n")
            self.mode_pending = "boot"
            self.mode_deadline = time.monotonic() + MODE_TIMEOUT
            self.update_flash_button()
            self.log("Boot command sent; waiting for bootloader header")
        except (serial.SerialException, OSError) as exc:
            self.log(f"Serial write failed: {exc}", error=True)

    def reset_device(self):
        if not self.serial_port:
            self.log("Connect to the device first", error=True)
            return
        if self.flashing or self.mode_pending or self.pending:
            return
        if not self.bootloader_active:
            self.log("Bootloader is not active", error=True)
            return
        try:
            self.serial_port.write(encode(CMD_RESET))
            self.bootloader_active = False
            self.mode_pending = None
            self.device_header = None
            self.device_info = None
            self.parser = Parser()
            self.show_header(None, file=False)
            self.show_device_info()
            self.update_flash_button()
            self.log("Application start requested; command sent")
        except (serial.SerialException, OSError) as exc:
            self.log(f"Serial write failed: {exc}", error=True)

    def start_flash(self):
        if not self.ui.btn_flash.isEnabled():
            return
        warning = hardware_warning(self.file_header, self.device_header)
        if warning:
            answer = QMessageBox.warning(
                self, "Hardware version warning",
                f"{warning}\n\nContinue flashing?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
            # Serial polling continues while the modal dialog is open.
            if not self.ui.btn_flash.isEnabled():
                return
        self.flashing = True
        self.page_index = 0
        self.update_flash_button()
        self.send_request(CMD_BEGIN, self.file_header.to_bytes(), 0xffff, "begin")

    def send_request(self, command: int, data: bytes, seq: int, kind: str, expected_locks=None):
        self.pending = {"packet": encode(command, data), "seq": seq, "kind": kind,
                        "attempts": 0, "deadline": 0.0, "expected_locks": expected_locks}
        self.resend()

    def resend(self):
        if not self.pending or not self.serial_port:
            return
        if self.pending["attempts"] >= RETRIES:
            self.fail_flash(f"No ACK for {self.pending['kind']} after {RETRIES} attempts")
            return
        try:
            self.serial_port.write(self.pending["packet"])
        except (serial.SerialException, OSError) as exc:
            self.fail_flash(f"Serial write failed: {exc}")
            return
        self.pending["attempts"] += 1
        delay = FINISH_TIMEOUT if self.pending["kind"] == "finish" else PACKET_TIMEOUT
        self.pending["deadline"] = time.monotonic() + delay

    def send_next_page(self):
        if self.page_index == len(self.pages):
            count = len(self.pages)
            self.send_request(CMD_FINISH, count.to_bytes(2, "little"), count, "finish")
            return
        index = self.page_index
        ciphertext, tag = self.pages[index]
        self.send_request(CMD_PAGE, index.to_bytes(2, "little") + ciphertext + tag,
                          index, "page")

    def fail_flash(self, message: str):
        if self.pending and self.pending["kind"] in ("info", "lock"):
            self.device_info = None
            self.show_device_info()
        self.pending = None
        self.flashing = False
        self.update_flash_button()
        self.log(message, error=True)

    def poll_serial(self):
        if not self.serial_port:
            return
        try:
            data = self.serial_port.read(self.serial_port.in_waiting or 0)
        except (serial.SerialException, OSError) as exc:
            self.log(f"Serial read failed: {exc}", error=True)
            self.connect_serial()
            return
        for packet in self.parser.feed(data):
            self.handle_packet(packet)
        if self.pending and time.monotonic() >= self.pending["deadline"]:
            self.resend()
        if self.mode_pending and time.monotonic() >= self.mode_deadline:
            mode = self.mode_pending
            self.mode_pending = None
            self.update_flash_button()
            self.log(f"{mode.capitalize()} transition not confirmed", error=True)

    def handle_packet(self, packet):
        if packet.command == CMD_INFO:
            if not self.bootloader_active:
                return
            try:
                info = DeviceInfo.from_bytes(packet.payload)
            except ValueError:
                return
            sync_targets = self.device_info is None and self.pending is None
            self.device_info = info
            if self.pending and self.pending["kind"] == "info":
                sync_targets = True
                expected = self.pending.get("expected_locks")
                if expected is not None:
                    if info.lock_bits & 0x3f == expected:
                        self.log("Hardware lock modes verified")
                    else:
                        self.log("Lock readback did not match the requested modes", error=True)
                self.pending = None
            if sync_targets:
                self.sync_lock_targets(info)
            self.show_device_info()
            self.update_flash_button()
            return
        if packet.command == CMD_HEADER and len(packet.payload) == HEADER_SIZE:
            try:
                header = Header.from_bytes(packet.payload)
            except ValueError:
                header = None
            if not self.bootloader_active:
                self.log("Bootloader detected")
            self.bootloader_active = True
            if self.mode_pending == "boot":
                self.mode_pending = None
                self.log("Bootloader transition confirmed")
            self.device_header = header
            self.show_header(header, file=False)
            self.update_flash_button()
            return
        if not self.pending or packet.command not in (CMD_ACK, CMD_NACK):
            return
        if len(packet.payload) != (2 if packet.command == CMD_ACK else 3):
            return
        if packet.command == CMD_ACK and self.pending["kind"] == "info":
            return
        seq = int.from_bytes(packet.payload[:2], "little")
        if seq != self.pending["seq"] and not (packet.command == CMD_NACK and seq == 0xffff):
            return
        if packet.command == CMD_NACK:
            reason = packet.payload[2] if len(packet.payload) >= 3 else 0
            if reason == NACK_PACKET:
                self.resend()
            else:
                self.fail_flash(f"Device rejected {self.pending['kind']} ({reason})")
            return
        kind = self.pending["kind"]
        expected_locks = self.pending.get("expected_locks")
        self.pending = None
        if kind == "begin":
            self.log("Transfer started")
            self.send_next_page()
        elif kind == "page":
            self.page_index += 1
            if self.page_index == len(self.pages) or self.page_index % 16 == 0:
                self.log(f"Verified {self.page_index}/{len(self.pages)} pages")
            self.send_next_page()
        elif kind == "lock":
            self.log("Lock command acknowledged; reading physical lock bits")
            self.device_info = None
            self.send_request(CMD_INFO, b"", CONTROL_SEQ, "info", expected_locks=expected_locks)
            self.update_flash_button()
        elif kind == "finish":
            self.flashing = False
            self.bootloader_active = False
            self.device_header = self.file_header
            self.device_info = None
            self.show_device_info()
            self.show_header(self.device_header, file=False)
            self.update_flash_button()
            self.log("Firmware verified; device will start shortly")

    def closeEvent(self, event):
        if self.serial_port:
            self.serial_port.close()
        super().closeEvent(event)


if __name__ == "__main__":
    app = create_gui_application(sys.argv)
    window = MyFlasherApp()
    window.show()
    sys.exit(app.exec_())
