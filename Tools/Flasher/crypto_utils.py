from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class CryptoUtils:
    @staticmethod
    def sha256(data: bytes) -> bytes:
        """
        SHA256 hash fonksiyonunu kullanarak veriyi hashler.
        :param data: Hash'lenecek veri.
        :return: SHA256 hash'lenmiş veri.
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()

    @staticmethod
    def decrypt_with_rsa_private_key(data: bytes, private_key):
        """
        RSA özel anahtarıyla veriyi çözer.
        :param data: Şifreli veri.
        :param private_key: RSA özel anahtarı.
        :return: Şifre çözülmüş veri.
        """
        return private_key.decrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        AES-128-CBC algoritmasını kullanarak veriyi çözer.
        :param data: Şifreli veri.
        :param key: AES anahtarı (16 byte).
        :param iv: AES IV (16 byte).
        :return: Şifre çözülmüş veri.
        """
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    @staticmethod
    def unpad_data(data: bytes) -> bytes:
        """
        PKCS7 padding ile doldurulmuş veriyi padding'den arındırır.
        :param data: Padding yapılmış veri.
        :return: Padding'den arındırılmış veri.
        """
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(data) + unpadder.finalize()

    @staticmethod
    def encrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        AES-128-CBC algoritmasıyla veriyi şifreler.
        :param data: Şifrelenecek veri.
        :param key: AES anahtarı (16 byte).
        :param iv: AES IV (16 byte).
        :return: Şifreli veri.
        """
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    @staticmethod
    def pad_data(data: bytes) -> bytes:
        """
        Veriyi PKCS7 padding ile doldurur.
        :param data: Padding yapılacak veri.
        :return: Padding yapılmış veri.
        """
        padder = padding.PKCS7(128).padder()
        return padder.update(data) + padder.finalize()
    