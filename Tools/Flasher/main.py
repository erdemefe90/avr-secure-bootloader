import sys
import os
import serial
import utils
import serial.tools.list_ports
from PyQt5.QtWidgets import QApplication, QDialog, QMessageBox, QFileDialog, QCheckBox
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt
from Flasher_GUI import Ui_Dialog
from image_extract import extract
from crypto_utils import CryptoUtils

STX = 0xAA
BOOT_CMD_HEADER = 0xb0
BOOT_CMD_INFO = 0xb1
BOOT_CMD_FLASH = 0xb3
BOOT_CMD_ACK = 0xb5
BOOT_CMD_NACK = 0xb6
BOOT_CMD_RESET = 0xb7

BLOCK_SIZE = 128
AES_KEY = bytes.fromhex("b54df8139e124c6ce74519e27d5e0b01")

def create_packet(cmd: int, data: bytes) -> bytes:
    length = len(data)
    full_data = bytes([STX, cmd, length]) + data
    crc = utils.crc16_ccitt(full_data)
    return full_data + crc.to_bytes(2, byteorder='little')

class FlashThread(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str, str)
    finished = pyqtSignal(bool, str)

    def __init__(self, serial_port, encrypted_data, iv, mac, lock_bits=False):
        super().__init__()
        self.serial_port = serial_port
        self.encrypted_data = encrypted_data
        self.iv = iv
        self.mac = mac
        self.lock_bits = lock_bits
        self.nonce = None
        self.running = True

    def wait_for_packet(self, expected_cmd, timeout=2.0):
        import time
        start = time.time()
        buffer = bytearray()
        while time.time() - start < timeout and self.running:
            if self.serial_port.in_waiting > 0:
                b = self.serial_port.read(1)[0]
                if not buffer and b != STX: continue
                buffer.append(b)
                if len(buffer) >= 3:
                    expected_len = buffer[2]
                    if len(buffer) == 5 + expected_len:
                        received_crc = int.from_bytes(buffer[-2:], 'little')
                        if utils.crc16_ccitt(buffer[:-2]) == received_crc:
                            if buffer[1] == expected_cmd: return buffer[3:3+expected_len]
                            if buffer[1] == BOOT_CMD_NACK: return None
                        buffer = bytearray()
            time.sleep(0.001)
        return None

    def run(self):
        try:
            # 1. Send INFO to get Nonce
            # Payload: image_size (4) + IV (16)
            image_size = len(self.encrypted_data)
            payload = image_size.to_bytes(4, 'little') + self.iv
            self.serial_port.write(create_packet(BOOT_CMD_INFO, payload))
            
            self.nonce = self.wait_for_packet(BOOT_CMD_ACK)
            if not self.nonce:
                self.finished.emit(False, "Failed to get Nonce from Bootloader")
                return
            
            self.log.emit(f"Nonce received: {self.nonce.hex()}", "info")

            # 2. Flash blocks
            total_blocks = (len(self.encrypted_data) + BLOCK_SIZE - 1) // BLOCK_SIZE
            for i in range(total_blocks):
                if not self.running: return
                offset = i * BLOCK_SIZE
                remaining = len(self.encrypted_data) - offset
                chunk_len = min(BLOCK_SIZE, remaining)
                chunk = self.encrypted_data[offset:offset+chunk_len]
                
                is_last = (offset + chunk_len >= len(self.encrypted_data))
                offset_val = offset | (0x80000000 if is_last else 0)
                
                # Payload: len (1) + offset (4) + data (N)
                payload = bytes([chunk_len]) + offset_val.to_bytes(4, 'little') + chunk
                self.serial_port.write(create_packet(BOOT_CMD_FLASH, payload))
                
                if self.wait_for_packet(BOOT_CMD_ACK) is None:
                    self.finished.emit(False, f"Error at block {i}")
                    return
                
                self.progress.emit(int((i+1)/total_blocks * 100))

            self.finished.emit(True, "Flashing completed successfully!")
            
        except Exception as e:
            self.finished.emit(False, str(e))

class MyFlasherApp(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.serial_port = None
        self.encrypted_data = None
        self.header_data = None
        self.iv = None
        self.mac = None
        self.dev_header = None
        self.bootloader_active = False

        # Add Lock Bits checkbox
        self.chk_lock = QCheckBox("Lock Bits", self)
        self.chk_lock.setGeometry(10, 230, 100, 21)
        
        self.ui.btn_connect.clicked.connect(self.connect_serial)
        self.ui.btn_key.clicked.connect(self.select_key_file)
        self.ui.btn_img.clicked.connect(self.select_image_file)
        self.ui.btn_bootloader.clicked.connect(self.go_bootloader)
        self.ui.btn_app.clicked.connect(self.reset)
        self.ui.btn_flash.clicked.connect(self.start_flash)
        self.ui.btn_flash.setEnabled(False)

        self.ui.cb_baudrate.addItems(["9600", "19200", "38400", "57600", "115200"])
        self.ui.cb_baudrate.setCurrentText("115200")

        self.port_timer = QTimer()
        self.port_timer.timeout.connect(self.refresh_ports)
        self.port_timer.start(1000)
        self.refresh_ports()

    def log(self, message, level="info"):
        color = {"info": "black", "warning": "orange", "error": "red"}.get(level, "black")
        self.ui.tx_log.append(f"<span style='color:{color}'>{message}</span>")

    def refresh_ports(self):
        if self.serial_port and self.serial_port.is_open: return
        ports = [p.device for p in serial.tools.list_ports.comports()]
        if [self.ui.cb_port.itemData(i) for i in range(self.ui.cb_port.count())] != ports:
            self.ui.cb_port.clear()
            for p in ports: self.ui.cb_port.addItem(p, p)

    def connect_serial(self):
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.close()
            self.ui.btn_connect.setText("Connect")
            return
        try:
            port = self.ui.cb_port.currentData()
            baud = int(self.ui.cb_baudrate.currentText())
            self.serial_port = serial.Serial(port, baud, timeout=0.1)
            self.ui.btn_connect.setText("Disconnect")
            self.log(f"Connected to {port}")
            
            # Start listener for Header
            self.listen_timer = QTimer()
            self.listen_timer.timeout.connect(self.check_for_header)
            self.listen_timer.start(100)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def check_for_header(self):
        if not self.serial_port or not self.serial_port.is_open: return
        if self.serial_port.in_waiting >= 5:
            b = self.serial_port.read(1)[0]
            if b == STX:
                header = self.serial_port.read(2)
                cmd, length = header[0], header[1]
                data = self.serial_port.read(length + 2)
                if cmd == BOOT_CMD_HEADER:
                    self.dev_header = extract.parse_image_header(data[:-2], self.ui.lb_dev_sw.parent().findChildren(QLabel))
                    self.bootloader_active = True
                    self.ui.btn_flash.setEnabled(True)
                    self.log("Bootloader detected.")
                    self.listen_timer.stop()

    def select_key_file(self):
        self.log("Key file no longer required for new AES-CTR protocol.", "warning")

    def select_image_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Binary (*.bin)")
        if path:
            self.ui.ln_img.setText(path)
            res = extract.process_image_file(path, self.log)
            if res[0]:
                self.encrypted_data, self.header_data, self.iv, self.mac = res
                info = extract.parse_image_header(self.header_data, None)
                self.ui.lb_file_sw.setText(f"{info['sw_ver'][0]}.{info['sw_ver'][1]}.{info['sw_ver'][2]}")
                self.ui.lb_file_hw.setText(f"{info['hw_ver'][0]}.{info['hw_ver'][1]}.{info['hw_ver'][2]}")
                self.ui.lb_file_size.setText(f"{info['size']} bytes")
                self.file_info = info

    def start_flash(self):
        if not self.bootloader_active: return
        
        # Version check
        if self.dev_header and not self.ui.radioButton.isChecked():
            v1 = self.dev_header['sw_ver']
            v2 = self.file_info['sw_ver']
            if v2 < v1:
                if QMessageBox.warning(self, "Warning", "Downgrade detected! Continue?", QMessageBox.Yes|QMessageBox.No) == QMessageBox.No:
                    return
            elif v2 == v1:
                self.log("Same version detected. Use Force to re-flash.", "warning")
                return

        self.ui.btn_flash.setEnabled(False)
        self.flash_thread = FlashThread(self.serial_port, self.encrypted_data, self.iv, self.mac, self.chk_lock.isChecked())
        self.flash_thread.log.connect(self.log)
        self.flash_thread.finished.connect(self.flash_finished)
        self.flash_thread.start()

    def flash_finished(self, success, message):
        self.ui.btn_flash.setEnabled(True)
        if success: QMessageBox.information(self, "Success", message)
        else: QMessageBox.critical(self, "Error", message)

    def go_bootloader(self):
        if self.serial_port: self.serial_port.write(b'BOOT\n')

    def reset(self):
        if self.serial_port: self.serial_port.write(create_packet(BOOT_CMD_RESET, b''))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    from PyQt5.QtWidgets import QLabel # Fix for dynamic lookup
    ex = MyFlasherApp()
    ex.show()
    sys.exit(app.exec_())
