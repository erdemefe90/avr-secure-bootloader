import struct
import sys
import argparse
import os
from intelhex import IntelHex

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

IMAGE_HEADER_OFFSET = 104
IMAGE_HEADER_SIZE = 56 
IMAGE_SIZE_FIELD_OFFSET = IMAGE_HEADER_OFFSET + 16
INTEGRITY_FIELD_OFFSET = IMAGE_HEADER_OFFSET + (IMAGE_HEADER_SIZE - 2)

AES_BLOCK_SIZE = 16
AES_KEY = bytes.fromhex("b54df8139e124c6ce74519e27d5e0b01") 

def aes_cbc_mac(data: bytes, key: bytes) -> bytes:
    iv = bytes([0] * 16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    output = encryptor.update(data) + encryptor.finalize()
    return output[-16:]

def pad_data(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    if pad_len == 0:
        return data
    return data + bytes([0x80]) + bytes([0] * (pad_len - 1))

def encrypt_aes_ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
    # Use CTR mode for encryption/decryption consistency
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def main():
    parser = argparse.ArgumentParser(description="Encrypt image for secure bootloader.")
    parser.add_argument("-f", "--file", required=True, help="Input plaintext hex file")
    parser.add_argument("-k", "--key", help="Optional key (ignored)", required=False)

    args = parser.parse_args()
    input_path = args.file
    output_path = input_path.replace(".hex", "_encrypted.bin")

    hex_data = IntelHex(input_path)
    data = bytearray(hex_data.tobinarray())

    total_size = len(data)
    struct.pack_into("<I", data, IMAGE_SIZE_FIELD_OFFSET, total_size)
    struct.pack_into("<H", data, INTEGRITY_FIELD_OFFSET, 0)

    header_copy = data[IMAGE_HEADER_OFFSET:IMAGE_HEADER_OFFSET + IMAGE_HEADER_SIZE]

    # Padding
    padded_data = pad_data(data)
    
    # Calculate CBC-MAC over padded plaintext
    signature = aes_cbc_mac(padded_data, AES_KEY)

    # Encrypt using CTR
    # IV in CTR is usually 16 bytes (Nonce + Counter)
    iv_aes128 = os.urandom(AES_BLOCK_SIZE)
    encrypted_data = encrypt_aes_ctr(padded_data, AES_KEY, iv_aes128)

    # Final Payload: [Encrypted Data] [Header] [IV] [CBC-MAC]
    final_payload = encrypted_data + header_copy + iv_aes128 + signature

    with open(output_path, "wb") as f:
        f.write(final_payload)

    print(f"Encrypted image (CTR+CBC-MAC): {output_path}")
    print(f"Original: {total_size}, Final: {len(final_payload)}")

if __name__ == "__main__":
    main()
