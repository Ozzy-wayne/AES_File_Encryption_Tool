from utils.encryption import encrypt_bytes, decrypt_bytes
from utils.hashing import derive_key
import config, os

def test_encrypt_decrypt_bytes():
    password = "hello123"
    salt = os.urandom(config.SALT_LENGTH)
    key = derive_key(password, salt)
    data = b"secret message"

    # DEBUG PRINT
    print("=== ENCRYPTION DEBUG ===")
    print("Password:", password)
    print("Salt (hex):", salt.hex())
    print("Derived Key (hex):", key.hex())

    enc = encrypt_bytes(data, key)
    print("IV (hex):", enc["iv"].hex())
    print("Ciphertext (hex):", enc["ciphertext"].hex())
    print("Auth Tag (hex):", enc["tag"].hex())

    decrypted = decrypt_bytes(enc["ciphertext"], key, enc["iv"], enc["tag"])
    print("Decrypted Data:", decrypted)
    print("========================")

    assert decrypted == data
