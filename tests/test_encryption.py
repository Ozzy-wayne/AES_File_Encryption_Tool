from utils.encryption import encrypt_bytes, decrypt_bytes
from utils.hashing import derive_key
import config, os

def test_encrypt_decrypt_bytes():
    password = "hello123"
    salt = os.urandom(config.SALT_LENGTH)
    key = derive_key(password, salt)

    data = b"secret message"
    enc = encrypt_bytes(data, key)

    decrypted = decrypt_bytes(enc["ciphertext"], key, enc["iv"], enc["tag"])
    assert decrypted == data
