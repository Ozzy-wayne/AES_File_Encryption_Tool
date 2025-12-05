from Crypto.Hash import SHA256  
from Crypto.Protocol.KDF import PBKDF2
import config

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive AES-256 key from password using PBKDF2-HMAC-SHA256
    """
    key = PBKDF2(
        password, 
        salt, 
        dkLen=config.KEY_LENGTH, 
        count=config.PBKDF2_ITERATIONS, 
        hmac_hash_module=SHA256
    )
    return key
