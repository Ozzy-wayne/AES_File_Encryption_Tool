from utils.hashing import derive_key
import config
import os

def test_derive_key():
    password = "test123"
    salt = os.urandom(config.SALT_LENGTH)
    key = derive_key(password, salt)

    # DEBUG PRINT
    print("=== HASHING DEBUG ===")
    print("Password:", password)
    print("Salt (hex):", salt.hex())
    print("Derived Key (hex):", key.hex())
    print("=====================")

    # Test passes
    assert len(key) == config.KEY_LENGTH
