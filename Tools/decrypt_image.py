import sys
import argparse
import hashlib

from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

AES_BLOCK_SIZE = 16
RSA_ENCRYPTED_KEY_SIZE = 256  # 2048 bit RSA
IV_SIZE = 16
HASH_SIZE = 32
HEADER_SIZE = 88

def hexdump(data: bytes, length=16):
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        ascii_bytes = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f"{i:08x}  {hex_bytes:<48}  |{ascii_bytes}|")
    return '\n'.join(lines)

def unpad_data(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def decrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def decrypt_with_rsa_private_key(data: bytes, private_key) -> bytes:
    return private_key.decrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def main():
    parser = argparse.ArgumentParser(description="Decrypt image bin file.")
    parser.add_argument("-f", "--file", required=True, help="Encrypted image bin file")
    parser.add_argument("-k", "--key", required=True, help="RSA2048 private key (.pem)")
    args = parser.parse_args()

    input_path = args.file
    private_key_path = args.key
    output_path = input_path.replace("_encrypted.bin", "_decrypted.bin")

    with open(input_path, "rb") as f:
        encrypted_content = f.read()

    # SHA256 control
    final_hash = encrypted_content[-HASH_SIZE:]
    encrypted_payload = encrypted_content[:-HASH_SIZE]
    if sha256(encrypted_payload) != final_hash:
        print("Error: SHA256 verification failed.")
        sys.exit(1)

    rsa_encrypted_key = encrypted_payload[-RSA_ENCRYPTED_KEY_SIZE:]
    encrypted_block = encrypted_payload[:-RSA_ENCRYPTED_KEY_SIZE]

    # Install RSA private key
    with open(private_key_path, "rb") as f:
        key_data = f.read()
        private_key = serialization.load_pem_private_key(key_data, password=None)

    aes_key_iv = decrypt_with_rsa_private_key(rsa_encrypted_key, private_key)
    aes256_key = aes_key_iv[:32]
    aes256_iv = aes_key_iv[32:48]

    decrypted_secure_block_padded = decrypt_aes_cbc(encrypted_block, aes256_key, aes256_iv)
    secure_block = unpad_data(decrypted_secure_block_padded)

    # Secure block -> [encrypted_data + CRC] + [header] + [iv_aes128] + [hash1]
    encrypted_data_with_crc = secure_block[:-(HEADER_SIZE + IV_SIZE + HASH_SIZE)]
    header = secure_block[-(HEADER_SIZE + IV_SIZE + HASH_SIZE):- (IV_SIZE + HASH_SIZE)]
    iv_aes128 = secure_block[-(IV_SIZE + HASH_SIZE):-HASH_SIZE]
    hash1 = secure_block[-HASH_SIZE:]

    # CRC kontrolü (only for encrypted_data_with_crc)
    received_crc = int.from_bytes(encrypted_data_with_crc[-2:], byteorder='little')
    calculated_crc = crc16_ccitt(encrypted_data_with_crc[:-2])
    if received_crc != calculated_crc:
        print(f"Error: CRC16 verification failed. Expected: {received_crc:#06x}, Calculated: {calculated_crc:#06x}")
        sys.exit(1)

    # Hash1 Control
    if sha256(encrypted_data_with_crc) != hash1:
        print("Error: SHA256 verification failed.")
        sys.exit(1)

    # Remove the last 2 byte CRC
    encrypted_data = encrypted_data_with_crc[:-2]

    decrypted_padded_data = decrypt_aes_cbc(encrypted_data, AES_KEY, iv_aes128)
    original_data = unpad_data(decrypted_padded_data)

    original_crc = original_data[-2:]
    calculated_crc = crc16_ccitt(original_data[:-2])
    if original_crc != calculated_crc.to_bytes(2, byteorder='little'):
        print(f"Error: CRC16 verification failed. Expected: {received_crc:#06x}, Calculated: {calculated_crc:#06x}")
        sys.exit(1)
    else:
        with open(output_path, "wb") as f:
            f.write(original_data[:-2])
        print(hexdump(original_data))
        print(f"File decrypted and saved to: {output_path}")


if __name__ == "__main__":
    AES_KEY = bytes.fromhex("b54df8139e124c6ce74519e27d5e0b01")
    main()
