import sys
import os
import serial
import utils
import serial.tools.list_ports
from PyQt5.QtWidgets import QApplication, QDialog, QMessageBox, QFileDialog, QLabel
from PyQt5.QtCore import QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QIcon
from Flasher_GUI import Ui_Dialog
from image_extract import extract

STX = 0xAA

BOOT_CMD_HEADER = 0xb0
BOOT_CMD_INFO = 0xb1
BOOT_CMD_FLASH = 0xb3
BOOT_CMD_ACK = 0xb5
BOOT_CMD_NACK = 0xb6
BOOT_CMD_RESET = 0xb7

BLOCK_SIZE = 128


class LabelGroup:
    def __init__(self, lb_sw, lb_hw, lb_size, lb_compiler_ver, lb_compile_time):
        self.lb_sw = lb_sw
        self.lb_hw = lb_hw
        self.lb_size = lb_size
        self.lb_compiler_ver = lb_compiler_ver
        self.lb_compile_time = lb_compile_time

def create_packet(cmd: int, data: bytes) -> bytes:
    length = len(data)
    header = bytes([STX, cmd, length])
    full_data = header + data
    crc = utils.crc16_ccitt(full_data)
    crc_bytes = crc.to_bytes(2, byteorder='little')
    return full_data + crc_bytes

class SerialReceiverThread(QThread):
    packet_received = pyqtSignal(bytes)

    def __init__(self, serial_port):
        super().__init__()
        self.serial_port = serial_port
        self.running = True
        self.rx_state = "WAIT_STX"  # Initial State
        self.rx_buffer = bytearray()
        self.expected_length = 0

    def run(self):
        while self.running:
            try:
                if self.serial_port and self.serial_port.in_waiting > 0:
                    data = self.serial_port.read(self.serial_port.in_waiting)
                    for byte in data:
                        self.parse(byte)
            except serial.SerialException as e:
                print(f"SerialException: {e}")
                self.running = False
            except OSError as e:
                print(f"OSError: {e}")
                self.running = False

    def parse(self, byte):
        
        if self.rx_state == "WAIT_STX":
            if byte == STX:  
                self.rx_buffer = bytearray([byte])  
                self.rx_state = "WAIT_CMD" 
        elif self.rx_state == "WAIT_CMD":
            self.rx_buffer.append(byte) 
            self.rx_state = "WAIT_LEN"
        elif self.rx_state == "WAIT_LEN":
            self.rx_buffer.append(byte) 
            self.expected_length = byte 
            if self.expected_length > (256 - 5):
                self.rx_state = "WAIT_STX"
            elif self.expected_length == 0:
                self.rx_state = "WAIT_CRC_L"
            else:
                self.rx_state = "WAIT_DATA"
        elif self.rx_state == "WAIT_DATA":
            self.rx_buffer.append(byte)
            if len(self.rx_buffer) == (3 + self.expected_length):
                self.rx_state = "WAIT_CRC_L"
        elif self.rx_state == "WAIT_CRC_L":
            self.rx_buffer.append(byte)
            self.rx_state = "WAIT_CRC_H"
        elif self.rx_state == "WAIT_CRC_H":
            self.rx_buffer.append(byte)

            crc_received = int.from_bytes(self.rx_buffer[-2:], byteorder="little")
            crc_calculated = utils.crc16_ccitt(self.rx_buffer[:-2])

            # CRC verifiy
            if crc_received == crc_calculated:
                self.packet_received.emit(bytes(self.rx_buffer))
            else:
            # print if CRC doesn't match.
                print(f"CRC error received: {hex(crc_received)} calculated: {hex(crc_calculated)}")

            self.rx_state = "WAIT_STX"  # Sonrasında yeniden STX beklemeye başla

    def process_packet(self, cmd, length, data):
        print(f"cmd: {cmd:#04x}, data: {data.hex()}, len: {len(data):#04x}")
            
        # Diğer komutlar için gerekli işlemleri ekleyin...

    def stop(self):
        self.running = False
        self.serial_port = None
        self.quit()

class MyFlasherApp(QDialog):
    def log(self, message, level="info", popup=False):
        color = {
            "info": "black",
            "warning": "orange",
            "error": "red"
        }.get(level, "black")

        self.ui.tx_log.append(f"<span style='color:{color}'>{message}</span>")

        if popup:
            if level == "info":
                QMessageBox.information(self, "Information", message)
            elif level == "warning":
                QMessageBox.warning(self, "Warning", message)
            elif level == "error":
                QMessageBox.critical(self, "Error", message)

    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)

        self.serial_port = None
        self.private_key = None
        self.encrypted_data = None
        self.header = None
        self.iv_aes128 = None
        self.image_size = None
        self.bootloader_active = False
        self.ui.btn_bootloader.clicked.connect(self.go_bootloader)
        self.ui.btn_app.clicked.connect(self.reset)
        self.ui.btn_flash.setEnabled(False)

        self.dev_labels = LabelGroup(
            lb_sw=self.ui.lb_dev_sw,
            lb_hw=self.ui.lb_dev_hw,
            lb_size=self.ui.lb_dev_size,
            lb_compiler_ver=self.ui.lb_dev_compiler_ver,
            lb_compile_time=self.ui.lb_dev_compile_time
        )

        self.file_labels = LabelGroup(
            lb_sw=self.ui.lb_file_sw,
            lb_hw=self.ui.lb_file_hw,
            lb_size=self.ui.lb_file_size,
            lb_compiler_ver=self.ui.lb_file_compiler_ver,
            lb_compile_time=self.ui.lb_file_compile_time
        )

        self.setWindowTitle("AVR Flasher")
        
        self.baudrates = [2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400]
        self.ui.cb_baudrate.addItems([str(b) for b in self.baudrates])
        self.ui.cb_baudrate.setCurrentIndex(6)  # Default to 115200
        self.ui.cb_baudrate.currentIndexChanged.connect(self.baudrate_changed)
        self.log(f"Baud Rate Selected: {self.ui.cb_baudrate.currentText()}", level="info")

        self.ui.btn_connect.clicked.connect(self.connect_serial)
        self.ui.btn_key.clicked.connect(self.select_key_file)
        self.ui.btn_img.clicked.connect(self.select_image_file)
        self.ui.btn_flash.clicked.connect(self.start_flash)

        self.port_check_timer = QTimer()
        self.port_check_timer.timeout.connect(self.refresh_ports)
        self.port_check_timer.start(2000)

        self.refresh_ports()

        if self.serial_port:
            self.receiver_thread = SerialReceiverThread(self.serial_port)
            self.receiver_thread.packet_received.connect(self.handle_packet)  # Callback for received packets
            self.receiver_thread.start()

    def refresh_ports(self):
        current_selection = self.ui.cb_port.currentData()
        self.ui.cb_port.clear()

        ports = list(serial.tools.list_ports.comports())
        for p in ports:
            self.ui.cb_port.addItem(f"{p.device} - {p.description}", p.device)

        if current_selection:
            index = self.ui.cb_port.findData(current_selection)
            if index >= 0:
                self.ui.cb_port.setCurrentIndex(index)

    def connect_serial(self):
        if self.serial_port and self.serial_port.is_open:
            try:
                self.serial_port.close()
                self.serial_port = None
                self.ui.btn_connect.setText("Connect")
                self.ui.cb_baudrate.setEnabled(True)
                self.receiver_thread.stop()
                self.log("Serial connection closed.", level="info")
                return
            except Exception as e:
                self.log(f"Error while closing connection:\n{str(e)}", level="error", popup=True)
                return

        idx = self.ui.cb_port.currentIndex()
        if idx == -1:
            self.log("Please select a port first", level="warning")
            return

        port_device = self.ui.cb_port.currentData()
        baudrate = int(self.ui.cb_baudrate.currentText())

        try:
            self.serial_port = serial.Serial(port_device, baudrate=baudrate, timeout=1)
            if self.serial_port.is_open:
                self.receiver_thread = SerialReceiverThread(self.serial_port)
                self.receiver_thread.packet_received.connect(self.handle_packet)
                self.receiver_thread.start()  # Start thread
                self.ui.btn_connect.setText("Disconnect")
                self.ui.cb_baudrate.setEnabled(False)
                self.log(f"Connected to port {port_device}", level="info")
        except serial.SerialException as e:
            self.log(f"Connection failed: {str(e)}", level="error", popup=True)

    def baudrate_changed(self):
        if self.serial_port and self.serial_port.is_open:
            return  # Do nothing if serial connection is open
        baudrate = self.ui.cb_baudrate.currentText()
        self.log(f"Baud Rate Changed to: {baudrate}", level="info")

    def select_key_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Select Private Key",
            "",
            "Key Files (*.pem)"
        )
        if file_name:
            self.ui.ln_key.setText(file_name)
            try:
                self.private_key = extract.load_private_key_from_file(file_name)
                self.log("Private key loaded successfully.", level="info")
            except Exception as e:
                self.log(f"Failed to load private key: {e}", level="error", popup=True)

    def select_image_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Select Image File",
            "",
            "Binary Files (*.bin)"
        )
        if file_name:
            self.ui.ln_img.setText(file_name)
            if not self.private_key:
                self.log("Please load a private key first!", level="warning", popup=True)
                return
            encrypted_data, header, aes128_iv = extract.process_image_file(file_name, self.private_key, self.log)
            if encrypted_data:
                self.encrypted_data = encrypted_data
                self.header = header
                self.iv_aes128 = aes128_iv
                self.log("Image file loaded and processed.", level="info")
                self.image_size = extract.parse_image_header(header, self.file_labels)
            else:
                self.log("Failed to process image file.", level="error")

    def parse_packet(self, packet: bytes):
        if len(packet) < 5:
            raise ValueError("Packet too short")

        if packet[0] != STX:
            raise ValueError("Incorrect STX")

        cmd = packet[1]
        length = packet[2]
        expected_len = 3 + length + 2

        if len(packet) != expected_len:
            raise ValueError(f"Packet length mismatch: {len(packet)} vs {expected_len}")

        data = packet[3:3 + length]
        received_crc = int.from_bytes(packet[-2:], byteorder='little')
        calculated_crc = utils.crc16_ccitt(packet[:-2])

        if received_crc != calculated_crc:
            raise ValueError(f"CRC error Received: {received_crc:04X}, Expected: {calculated_crc:04X}")

        return cmd, data

    def handle_packet(self, packet):
        try:
            cmd, data = self.parse_packet(packet)

            if cmd == BOOT_CMD_HEADER:
                self.header = data
                extract.parse_image_header(data, self.dev_labels) 
                if self.iv_aes128 and self.image_size:
                    payload = self.image_size.to_bytes(4, 'little') + self.iv_aes128
                    info_packet = create_packet(BOOT_CMD_INFO, payload)
                    self.serial_port.write(info_packet)
                    self.receiver_thread.expected_response_cmd = BOOT_CMD_ACK

                    # Start Timeout
                    self.boot_ack_timer = QTimer(self)
                    self.boot_ack_timer.setSingleShot(True)
                    self.boot_ack_timer.timeout.connect(self._boot_ack_timeout)
                    self.boot_ack_timer.start(2000)

            elif cmd == BOOT_CMD_ACK:
                if self.receiver_thread.expected_response_cmd == BOOT_CMD_ACK:
                    self.receiver_thread.bootloader_active = True
                    self.receiver_thread.expected_response_cmd = None
                    self.bootloader_active = True
                    self.ui.btn_flash.setEnabled(True)
                    self.log("Bootloader mode confirmed.", level="info")
                    if hasattr(self, "boot_ack_timer"):
                        self.boot_ack_timer.stop()
                elif self.waiting_for_block_ack:
                    self.waiting_for_block_ack = False
                    QTimer.singleShot(10, self.send_next_block)

        except ValueError as e:
            self.log(f"Packet parsing failed: {str(e)}", level="error")

    def _boot_ack_timeout(self):
        if not self.bootloader_active:
            self.log("Timeout: Bootloader ACK not received.", level="warning", popup=True)
            
    def go_bootloader(self):
        if self.serial_port and self.serial_port.is_open:
            bootloader_cmd = b'BOOT\n'  # BOOT command
            self.serial_port.write(bootloader_cmd)
            self.log("Sent BOOT command to switch to bootloader.", level="info")
        else:
            self.log("Serial port is not open.", level="error", popup=True)

    def reset(self):
        if self.serial_port and self.serial_port.is_open:
            packet = create_packet(BOOT_CMD_RESET, b'')
            self.serial_port.write(packet)
            self.log("Sent RESET command to reset device.", level="info")
        else:
            self.log("Serial port is not open.", level="error", popup=True)

    def start_flash(self):
        if not self.bootloader_active:
            self.log("Device is not in bootloader mode!", level="error", popup=True)
            return

        self.block_index = 0
        self.waiting_for_block_ack = False
        self.send_next_block()

    def send_next_block(self):
        offset = self.block_index * BLOCK_SIZE
        if offset >= len(self.encrypted_data):
            self.log("All blocks sent successfully.", level="info", popup=True)
            return

        remaining = len(self.encrypted_data) - offset
        block_len = min(BLOCK_SIZE, remaining)
        block_data = self.encrypted_data[offset:offset + block_len]
        print(f"Sending block {self.block_index} (len={block_len}, offset={offset:#010x})")
        offset_val = offset
        if offset + block_len >= len(self.encrypted_data):  # last block
            offset_val |= 0x80000000

        payload = bytes([block_len]) + offset_val.to_bytes(4, 'little') + block_data
        packet = create_packet(BOOT_CMD_FLASH, payload)
        self.serial_port.write(packet)
        self.log(f"Sent block {self.block_index} (len={block_len}, offset={offset_val:#010x})", level="info")

        self.block_index += 1
        self.waiting_for_block_ack = True



if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MyFlasherApp()
    window.show()
    sys.exit(app.exec_())
