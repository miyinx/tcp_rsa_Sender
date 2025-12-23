from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
import base64
import os
import random
import string

class CryptoUtils:
    @staticmethod
    def load_rsa_key(key_path):
        with open(key_path, 'rb') as f:
            return RSA.import_key(f.read())

    @staticmethod
    def generate_des_key():
        # 生成8位随机字符，只包含ASCII字母和数字
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(8))

    @staticmethod
    def generate_rc4_key():
        # 生成8位随机字符，包含大小写字母和数字
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(8))

    @staticmethod
    def des_encrypt(data, key):
        # 确保密钥是8字节的ASCII字符串
        if len(key) != 8:
            raise ValueError("DES密钥必须是8字节")
        cipher = DES.new(key.encode('ascii'), DES.MODE_ECB)
        padded_data = pad(data.encode(), DES.block_size)
        return base64.b64encode(cipher.encrypt(padded_data))

    @staticmethod
    def des_decrypt(encrypted_data, key):
        # 确保密钥是8字节的ASCII字符串
        if len(key) != 8:
            raise ValueError("DES密钥必须是8字节")
        cipher = DES.new(key.encode('ascii'), DES.MODE_ECB)
        decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
        return unpad(decrypted_data, DES.block_size).decode()

    @staticmethod
    def rc4_encrypt(data, key):
        from Crypto.Cipher import ARC4
        cipher = ARC4.new(key.encode())
        return base64.b64encode(cipher.encrypt(data.encode()))

    @staticmethod
    def rc4_decrypt(encrypted_data, key):
        from Crypto.Cipher import ARC4
        cipher = ARC4.new(key.encode())
        return cipher.decrypt(base64.b64decode(encrypted_data)).decode()

    @staticmethod
    def rsa_encrypt(data, public_key):
        cipher = PKCS1_OAEP.new(public_key)
        return base64.b64encode(cipher.encrypt(data.encode()))

    @staticmethod
    def rsa_decrypt(encrypted_data, private_key):
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(base64.b64decode(encrypted_data)).decode()

    @staticmethod
    def sign_data(data, private_key):
        hash_obj = SHA1.new(data.encode())
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return base64.b64encode(signature)

    @staticmethod
    def verify_signature(data, signature, public_key):
        hash_obj = SHA1.new(data.encode())
        try:
            pkcs1_15.new(public_key).verify(hash_obj, base64.b64decode(signature))
            return True
        except (ValueError, TypeError):
            return False 

    @staticmethod
    def calculate_sha1(data):
        hash_obj = SHA1.new(data.encode())
        return hash_obj.hexdigest() 