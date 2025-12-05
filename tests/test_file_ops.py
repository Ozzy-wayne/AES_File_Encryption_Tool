from utils.file_ops import write_encrypted_file, read_encrypted_file
import config, os

def test_file_write_read(tmp_path):
    # Create temp test file path
    test_path = tmp_path / "test.enc"

    salt = os.urandom(config.SALT_LENGTH)
    iv = os.urandom(config.IV_LENGTH)
    ciphertext = b"abc123"
    tag = os.urandom(16)

    # Write file
    write_encrypted_file(str(test_path), salt, iv, ciphertext, tag)
    print("=== FILE OPS DEBUG ===")
    print("Writing Encrypted File:")
    print("Salt (hex):", salt.hex())
    print("IV (hex):", iv.hex())
    print("Ciphertext (hex):", ciphertext.hex())
    print("Auth Tag (hex):", tag.hex())

    # Read file back
    out = read_encrypted_file(str(test_path))
    print("Reading Encrypted File:")
    print("Salt (hex):", out["salt"].hex())
    print("IV (hex):", out["iv"].hex())
    print("Ciphertext (hex):", out["ciphertext"].hex())
    print("Auth Tag (hex):", out["tag"].hex())
    print("=======================")

    # Assertions
    assert out["salt"] == salt
    assert out["iv"] == iv
    assert out["ciphertext"] == ciphertext
    assert out["tag"] == tag
