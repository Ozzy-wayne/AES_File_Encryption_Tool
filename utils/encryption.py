
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import config

def encrypt_bytes(data: bytes, key: bytes) -> dict:
    """
    Encrypt data using AES-256-GCM
    Returns: dict containing ciphertext, iv, auth_tag
    """
    iv = get_random_bytes(config.IV_LENGTH)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {"ciphertext": ciphertext, "iv": iv, "tag": tag}

def decrypt_bytes(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data
