import struct
import utils
from crypto_utils import CryptoUtils

AES_BLOCK_SIZE = 16
IV_SIZE = 16
MAC_SIZE = 16
IMAGE_HEADER_SIZE = 56
# Footer: Header (56) + IV (16) + MAC (16) = 88 bytes
FOOTER_SIZE = IMAGE_HEADER_SIZE + IV_SIZE + MAC_SIZE

IMAGE_HEADER_FORMAT = '<I 8s 4s I 12s 9s 6s 7s H' # Updated reserved area (7 bytes)
SW_VERSION_FORMAT = '<B B H I'
HW_VERSION_FORMAT = '<B B H'

class extract:
    @staticmethod
    def process_image_file(image_file: str, log_func):
        try:
            with open(image_file, "rb") as f:
                image = f.read()

            if len(image) < FOOTER_SIZE:
                log_func("Image file too short.", level="error", popup=True)
                return None, None, None, None

            # Split data
            encrypted_data = image[:-FOOTER_SIZE]
            footer = image[-FOOTER_SIZE:]
            
            header = footer[:IMAGE_HEADER_SIZE]
            iv = footer[IMAGE_HEADER_SIZE:IMAGE_HEADER_SIZE+IV_SIZE]
            mac = footer[IMAGE_HEADER_SIZE+IV_SIZE:]

            log_func(f"Image loaded: {len(encrypted_data)} bytes encrypted.", level="info")
            return encrypted_data, header, iv, mac
        except Exception as e:
            log_func(f"Error processing image: {e}", level="error", popup=True)
            return None, None, None, None

    @staticmethod
    def parse_image_header(data: bytes, labels):
        if len(data) < IMAGE_HEADER_SIZE:
            raise ValueError("Data too short for image_header_t")

        (
            magic,
            sw_version_raw,
            hw_version_raw,
            image_size,
            compile_date,
            compile_time,
            avr_gcc_version,
            reserved,
            integrity
        ) = struct.unpack(IMAGE_HEADER_FORMAT, data[:IMAGE_HEADER_SIZE])

        sw_major, sw_minor, sw_revision, sw_build = struct.unpack(SW_VERSION_FORMAT, sw_version_raw)
        hw_major, hw_minor, hw_revision = struct.unpack(HW_VERSION_FORMAT, hw_version_raw)

        sw_version_str = f"{sw_major}.{sw_minor}.{sw_revision}+{sw_build}"
        hw_version_str = f"{hw_major}.{hw_minor}.{hw_revision}"

        compile_date_str = compile_date.partition(b'\x00')[0].decode(errors='ignore').strip()
        compile_time_str = compile_time.partition(b'\x00')[0].decode(errors='ignore').strip()
        avr_gcc_version_str = avr_gcc_version.partition(b'\x00')[0].decode(errors='ignore').strip()

        if labels:
            labels.lb_sw.setText(sw_version_str)
            labels.lb_hw.setText(hw_version_str)
            labels.lb_size.setText(f"{image_size} bytes")
            labels.lb_compiler_ver.setText(avr_gcc_version_str)
            labels.lb_compile_time.setText(f"{compile_date_str} {compile_time_str}")

        return {
            "sw_ver": (sw_major, sw_minor, sw_revision, sw_build),
            "hw_ver": (hw_major, hw_minor, hw_revision),
            "size": image_size,
            "magic": magic
        }
