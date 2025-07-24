import struct
import sys
import argparse
import os
import hashlib
from intelhex import IntelHex

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

IMAGE_HEADER_OFFSET = 104
IMAGE_HEADER_SIZE = 88
IMAGE_SIZE_FIELD_OFFSET = IMAGE_HEADER_OFFSET + 16
CRC_FIELD_OFFSET = IMAGE_HEADER_OFFSET + (IMAGE_HEADER_SIZE - 2)

AES_BLOCK_SIZE = 16
AES_KEY = bytes.fromhex("b54df8139e124c6ce74519e27d5e0b01") 

def hexdump(data: bytes, length=16):
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        ascii_bytes = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f"{i:08x}  {hex_bytes:<48}  |{ascii_bytes}|")
    return '\n'.join(lines)

def crc_ccitt_16(data: bytes, poly=0x1021, init=0xFFFF) -> int:
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

def pad_data(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def encrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def encrypt_with_rsa_public_key(data: bytes, public_key) -> bytes:
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def main():
    parser = argparse.ArgumentParser(description="Encrypt image hex file for bootloader.")
    parser.add_argument("-f", "--file", required=True, help="Input plaintext hex file")
    parser.add_argument("-k", "--key", required=True, help="RSA2048 public key (.pem)")

    args = parser.parse_args()
    input_path = args.file
    rsa_pubkey_path = args.key
    output_path = input_path.replace(".hex", "_encrypted.bin")

    hex_data = IntelHex(input_path)
    data = bytearray(hex_data.tobinarray())

    total_size = len(data)

    # Update the image size area
    struct.pack_into("<I", data, IMAGE_SIZE_FIELD_OFFSET, total_size)

    # Calculate crc and write into image header
    crc_data = data[0:CRC_FIELD_OFFSET]
    crc_value = crc_ccitt_16(crc_data)
    struct.pack_into("<H", data, CRC_FIELD_OFFSET, crc_value)

    image_crc = crc_ccitt_16(data)
    data += image_crc.to_bytes(2, byteorder='little')

    # Save the plaintext file with size and crc
    output_plaintext = input_path.replace(".hex", "_filled.hex")
    plaintext_hex = IntelHex()
    plaintext_hex.frombytes(data, offset=0)
    plaintext_hex.write_hex_file(output_plaintext)

    # Copy the image header
    header_copy = data[IMAGE_HEADER_OFFSET:IMAGE_HEADER_OFFSET + IMAGE_HEADER_SIZE]

    # PKCS7 padding
    padded_data = pad_data(data)

    print(f"Padded data len:{len(padded_data)}")

    # Encrypt AES128-CBC with known key 
    iv_aes128 = os.urandom(AES_BLOCK_SIZE)
    encrypted_data = encrypt_aes_cbc(padded_data, AES_KEY, iv_aes128)

    # Calculate and add the encrypted file CRC
    encrypted_crc = crc_ccitt_16(encrypted_data)
    encrypted_data += struct.pack("<H", encrypted_crc)

    # Calculate SHA256
    hash1 = sha256(encrypted_data)

    # Encrypted data + header + IV + SHA256
    secure_block = encrypted_data + header_copy + iv_aes128 + hash1

    # PKCS7 padding for AES256
    secure_block_padded = pad_data(secure_block)

    # Encrypt with random AES256 key and IV
    aes256_key = os.urandom(32)
    aes256_iv = os.urandom(16)
    encrypted_block = encrypt_aes_cbc(secure_block_padded, aes256_key, aes256_iv)

    # Encrypt the secure AES keys with RSA
    with open(rsa_pubkey_path, "rb") as f:
        pubkey_data = f.read()
        try:
            pubkey = serialization.load_pem_public_key(pubkey_data)
            print("RSA Public key installed.")
        except Exception as e:
            print(f"RSA Public key failed: {e}")
            sys.exit(1)

    aes256_combo = aes256_key + aes256_iv  # 48 byte
    rsa_encrypted_section = encrypt_with_rsa_public_key(aes256_combo, pubkey)

    # Final SHA256
    final_payload = encrypted_block + rsa_encrypted_section
    final_hash = sha256(final_payload)

    with open(output_path, "wb") as f:
        f.write(final_payload + final_hash)

    print(f"Encrypted image written to: {output_path}")

if __name__ == "__main__":
    main()
