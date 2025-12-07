from Crypto.Hash import SHA256  
from Crypto.Protocol.KDF import PBKDF2
import config

def derive_key(password: str, salt: bytes) -> bytes:
    
    #Derive key from password user input and salt that using PBKDF2 with HMAC-SHA256
    key = PBKDF2(
        password, 
        salt, 
        dkLen=config.KEY_LENGTH, 
        count=config.PBKDF2_ITERATIONS, 
        hmac_hash_module=SHA256
    )
    return key
