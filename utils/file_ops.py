import os

def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def write_encrypted_file(path: str, salt: bytes, iv: bytes, ciphertext: bytes, tag: bytes):

    #Write encrypted file format: [SALT_LEN][SALT][IV_LEN][IV][CIPHERTEXT][TAG]
    with open(path, "wb") as f:
        f.write(len(salt).to_bytes(1, 'big'))
        f.write(salt)
        f.write(len(iv).to_bytes(1, 'big'))
        f.write(iv)
        f.write(ciphertext)
        f.write(tag)

def read_encrypted_file(path: str) -> dict:

    #Read encrypted file and extract salt, iv, ciphertext, and tag
    with open(path, "rb") as f:
        salt_len = int.from_bytes(f.read(1), 'big')
        salt = f.read(salt_len)
        iv_len = int.from_bytes(f.read(1), 'big')
        iv = f.read(iv_len)
        content = f.read()
        ciphertext = content[:-16]  # last 16 bytes = tag
        tag = content[-16:]
    return {"salt": salt, "iv": iv, "ciphertext": ciphertext, "tag": tag}

def file_exists(path: str) -> bool:

    #Check if file exists at given path
    return os.path.isfile(path)
