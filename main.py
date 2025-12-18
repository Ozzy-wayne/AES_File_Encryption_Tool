import os
import getpass
from utils.hashing import derive_key
from utils.encryption import encrypt_bytes, decrypt_bytes
from utils.file_ops import read_file, write_encrypted_file, read_encrypted_file, file_exists
from utils.password import check_password_strength
from Crypto.Random import get_random_bytes
import config

# Folder paths
SAMPLE_DIR = "sample_files"
ENCRYPTED_DIR = "encrypted_files"
DECRYPTED_DIR = "decrypted_files"

CHUNK_SIZE = 1024  # 1 KB per chunk


# Ensure folders exist
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

MAX_ATTEMPTS = 3

def get_password(confirm=False):
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        password = getpass.getpass(f"Enter password (attempt {attempts+1}/{MAX_ATTEMPTS}): ")

        # Check for empty password
        if not password:
            print("Password cannot be empty. Try again.\n")
            attempts += 1
            continue

        # Check password strength
        strength = check_password_strength(password)
        print(f"Password strength: {strength}")
        if strength == "Weak":
            print("Password too weak! Must be at least 8 chars, include uppercase, lowercase, number, symbol.\n")
            attempts += 1
            continue

        # Check to confirm password is correct or not
        if confirm:
            confirm_password = getpass.getpass("Confirm password: ")
            if password != confirm_password:
                print("Passwords do not match. Try again.\n")
                attempts += 1
                continue
        return password
    
    print("Maximum password attempts reached.\n")
    return None

def select_file_from_list(files, folder):
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        for i, f in enumerate(files, 1):
            path = os.path.join(folder, f)
            size = os.path.getsize(path)
            print(f"{i}. {f} ({size} bytes)")
        try:
            choice = int(input(f"Select a file by number (attempt {attempts+1}/{MAX_ATTEMPTS}): "))
            if 1 <= choice <= len(files):
                return files[choice - 1]
            else:
                print("\nInvalid selection. Try again.\n")
        except ValueError:
            print("\nInvalid input. Enter a number.\n")
        attempts += 1
        print("Available files:\n")
    print("Maximum attempts reached.\n")
    return None

def select_menu_option():
    attempts = 0
    while attempts < MAX_ATTEMPTS:

        #Banner of the tool
        print("******************************************************")
        print("**          AES-256 FILE ENCRYPTION TOOL            **")
        print("**        Secure • Authenticated • AES-GCM          **")
        print("******************************************************")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        choice = input(f"Select an option (attempt {attempts+1}/{MAX_ATTEMPTS}): ").strip()
        if choice in ["1", "2", "3"]:
            return choice
        print("\nInvalid option. Enter 1, 2, or 3.\n")
        attempts += 1
    print("Maximum attempts reached. Exiting.\n")
    return "3"

def encrypt_file(input_path: str, output_path: str):

    # Check if input file exists
    if not file_exists(input_path):
        print("Input file does not exist!\n")
        return

    # Get and confirm password from user 
    password = get_password(confirm=True)
    if not password:
        return
    
    data = read_file(input_path)
    salt = get_random_bytes(config.SALT_LENGTH)

    # Derive a 256-bit AES key from the password and salt using PBKDF2-HMAC-SHA256
    key = derive_key(password, salt)
    enc = encrypt_bytes(data, key)
    
    # Write the encrypted data to output file along with salt, iv, and tag
    write_encrypted_file(output_path, salt, enc["iv"], enc["ciphertext"], enc["tag"])
    print(f"\nEncryption successful! Saved to {output_path}\n")

def decrypt_file(input_path: str, output_path: str):

    # Check if input file exists 
    if not file_exists(input_path):
        print("Input file does not exist!\n")
        return

    attempts = 0

    # Read encrypted data from file
    enc_data = read_encrypted_file(input_path)

    # Try to get correct password and decrypt
    while attempts < MAX_ATTEMPTS:
        password = getpass.getpass(f"Enter password (attempt {attempts+1}/{MAX_ATTEMPTS}): ")
        if not password:
            print("Password cannot be empty. Try again.\n")
            attempts += 1
            continue

        # Derive key and attempt decryption 
        key = derive_key(password, enc_data["salt"])
        try:
            decrypted = decrypt_bytes(enc_data["ciphertext"], key, enc_data["iv"], enc_data["tag"])
            with open(output_path, "wb") as f:
                f.write(decrypted)
            print(f"\nDecryption successful! Saved to {output_path}\n")
            return
        except Exception:
            print("Decryption failed! Wrong password or file corrupted.\n")
            attempts += 1

    print("Maximum password attempts reached. Decryption aborted.\n")

def main_menu():
    while True:
        choice = select_menu_option()
        if choice == "1":

            # List available files to encrypt in sample_files directory
            files = [f for f in os.listdir(SAMPLE_DIR) if os.path.isfile(os.path.join(SAMPLE_DIR, f))]
            if not files:
                print("No files available to encrypt.\n")
                continue
            print("\nAvailable files:")

            # Let user select a file to encrypt
            file_name = select_file_from_list(files, SAMPLE_DIR)

            # If no valid file selected, continue
            if not file_name:
                continue

            # Encrypt the selected file and save to encrypted_files directory
            input_path = os.path.join(SAMPLE_DIR, file_name)
            output_path = os.path.join(ENCRYPTED_DIR, file_name + ".enc")
            encrypt_file(input_path, output_path)

        elif choice == "2":

            # List available files to decrypt in encrypted_files directory
            files = [f for f in os.listdir(ENCRYPTED_DIR) if os.path.isfile(os.path.join(ENCRYPTED_DIR, f))]
            if not files:
                print("No files available to decrypt.\n")
                continue
            print("\nAvailable files:")

            # Let user select a file to decrypt
            file_name = select_file_from_list(files, ENCRYPTED_DIR)
            if not file_name:
                continue

            # Decrypt the selected file and save to decrypted_files directory
            input_path = os.path.join(ENCRYPTED_DIR, file_name)
            output_file_name = file_name[:-4] if file_name.lower().endswith(".enc") else file_name
            output_path = os.path.join(DECRYPTED_DIR, output_file_name)
            decrypt_file(input_path, output_path)

        elif choice == "3":
            print("Thank You for Using AES-256 FILE ENCRYPTION TOOL!")
            break

if __name__ == "__main__":
    main_menu()
