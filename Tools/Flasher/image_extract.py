from crypto_utils import CryptoUtils, serialization
import utils
import struct
AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 32
RSA_ENCRYPTED_KEY_SIZE = 256  # 2048 bit RSA
IV_SIZE = 16
HASH_SIZE = 32

IMAGE_HEADER_FORMAT = '<I 8s 4s I 12s 9s 6s 39s H'
IMAGE_HEADER_SIZE = struct.calcsize(IMAGE_HEADER_FORMAT)

SW_VERSION_FORMAT = '<B B H I'  # major, minor, revision, build
HW_VERSION_FORMAT = '<B B H'    # major, minor, revision

class extract:

    def process_image_file(image_file: str, private_key, log_func):

        with open(image_file, "rb") as f:
            image = f.read()

        if len(image) < HASH_SIZE:
            log_func("Image file too short or corrupted.", level="error", popup=True)
            return None, None, None

        final_hash = image[-HASH_SIZE:]
        encrypted_payload = image[:-HASH_SIZE]

        if CryptoUtils.sha256(encrypted_payload) != final_hash:
            log_func("SHA256 verification failed for full image.", level="error", popup=True)
            return None, None, None

        # Ayrıştırma
        if len(encrypted_payload) < RSA_ENCRYPTED_KEY_SIZE:
            log_func("Encrypted payload too short.", level="error", popup=True)
            return None, None, None

        rsa_encrypted_key = encrypted_payload[-RSA_ENCRYPTED_KEY_SIZE:]
        encrypted_block = encrypted_payload[:-RSA_ENCRYPTED_KEY_SIZE]

        try:
            aes_key_iv = CryptoUtils.decrypt_with_rsa_private_key(rsa_encrypted_key, private_key)
        except Exception as e:
            log_func(f"RSA decryption failed: {e}", level="error", popup=True)
            return None, None, None

        aes256_key = aes_key_iv[:AES_KEY_SIZE]
        aes256_iv = aes_key_iv[AES_KEY_SIZE:AES_KEY_SIZE + IV_SIZE]
        log_func("AES256 key and IV decrypted with RSA.", level="info")

        try:
            decrypted_padded = CryptoUtils.decrypt_aes_cbc(encrypted_block, aes256_key, aes256_iv)
            decrypted = CryptoUtils.unpad_data(decrypted_padded)
        except Exception as e:
            log_func(f"AES decryption or unpadding failed: {e}", level="error", popup=True)
            return None, None, None

        # Secure block içinden parçalar
        # HEADER_SIZE + IV_SIZE + HASH_SIZE toplam 88+16+32 = 136 byte
        if len(decrypted) < (IMAGE_HEADER_SIZE + IV_SIZE + HASH_SIZE):
            log_func("Decrypted data too short.", level="error", popup=True)
            return None, None, None

        encrypted_data_with_crc = decrypted[:-(IMAGE_HEADER_SIZE + IV_SIZE + HASH_SIZE)]
        header = decrypted[-(IMAGE_HEADER_SIZE + IV_SIZE + HASH_SIZE):-(IV_SIZE + HASH_SIZE)]
        iv_aes128 = decrypted[-(IV_SIZE + HASH_SIZE):-HASH_SIZE]
        hash1 = decrypted[-HASH_SIZE:]

        if len(encrypted_data_with_crc) < 2:
            log_func("Encrypted data with CRC too short.", level="error", popup=True)
            return None, None, None

        received_crc = int.from_bytes(encrypted_data_with_crc[-2:], byteorder='little')
        calculated_crc = utils.crc16_ccitt(encrypted_data_with_crc[:-2])

        if received_crc != calculated_crc:
            log_func(f"CRC mismatch! received: {received_crc}, calculated: {calculated_crc}", level="error", popup=True)
            return None, None, None

        if CryptoUtils.sha256(encrypted_data_with_crc) != hash1:
            log_func("SHA256 mismatch for encrypted data with CRC", level="error", popup=True)
            return None, None, None
        
        encrypted_data = encrypted_data_with_crc[:-2]
        log_func(f"Image file processed successfully. Encrypted Length: {len(encrypted_data)} ", level="info")
        return encrypted_data, header, iv_aes128  # encrypted_data, header, iv_aes128
    
    @staticmethod
    def load_private_key_from_file(filepath: str):
        with open(filepath, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        
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
            crc
        ) = struct.unpack(IMAGE_HEADER_FORMAT, data[:IMAGE_HEADER_SIZE])

        # sw_version ayrıştır
        sw_major, sw_minor, sw_revision, sw_build = struct.unpack(SW_VERSION_FORMAT, sw_version_raw)

        # hw_version ayrıştır
        hw_major, hw_minor, hw_revision = struct.unpack(HW_VERSION_FORMAT, hw_version_raw)

        # Versiyon string'leri
        sw_version_str = f"{sw_major}.{sw_minor}.{sw_revision}+{sw_build}"
        hw_version_str = f"{hw_major}.{hw_minor}.{hw_revision}"

        # Derleme zamanı ve sürüm
        compile_date_str = compile_date.partition(b'\x00')[0].decode(errors='ignore').strip()
        compile_time_str = compile_time.partition(b'\x00')[0].decode(errors='ignore').strip()
        avr_gcc_version_str = avr_gcc_version.partition(b'\x00')[0].decode(errors='ignore').strip()

        # QLabel’lara yaz
        labels.lb_sw.setText(sw_version_str)
        labels.lb_hw.setText(hw_version_str)
        labels.lb_size.setText(f"{image_size} bytes")
        labels.lb_compiler_ver.setText(avr_gcc_version_str)
        labels.lb_compile_time.setText(f"{compile_date_str} {compile_time_str}")

        return image_size
