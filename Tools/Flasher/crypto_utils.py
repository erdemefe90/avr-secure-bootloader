from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CryptoUtils:
    @staticmethod
    def encrypt_aes_ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    @staticmethod
    def decrypt_aes_ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    @staticmethod
    def aes_cbc_mac(data: bytes, key: bytes) -> bytes:
        iv = bytes([0] * 16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        output = encryptor.update(data) + encryptor.finalize()
        return output[-16:]