from utils.file_ops import write_encrypted_file, read_encrypted_file
import config, os

def test_file_write_read(tmp_path):
    # create temp test file path
    test_path = tmp_path / "test.enc"

    salt = os.urandom(config.SALT_LENGTH)
    iv = os.urandom(config.IV_LENGTH)
    ciphertext = b"abc123"
    tag = os.urandom(16)

    write_encrypted_file(str(test_path), salt, iv, ciphertext, tag)
    out = read_encrypted_file(str(test_path))

    assert out["salt"] == salt
    assert out["iv"] == iv
    assert out["ciphertext"] == ciphertext
    assert out["tag"] == tag
