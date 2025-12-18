# AES-256-File-Encryption-Tool
This is my individual cryptography project.

#Project Overview
This Python CLI tool securely encrypts and decrypts files using AES-256-GCM encryption with PBKDF2-HMAC-SHA256 key derivation. It ensure your files remain private, and encryption keys are never stored, they are derived from the password each time.

## Key Features:
- AES-256-GCM encryption and decryption
- Password-based key derivation (PBKDF2-HMAC-SHA256)
- SHA-256 hashing for secure key handling
- CLI-based, supports any file type (text, PDF, images)
- Sample files included for demonstration
- Password strength validation
- Safe, self-contained encrypted file format

## Folder Structure

AES_File_Encryption_Tool/
│
├── README.md
├── requirements.txt
├── main.py
├── config.py
│
├── utils/
│ ├── encryption.py
│ ├── hashing.py
│ ├── file_ops.py
│ └── password.py
│
├── tests/
│ ├── init.py
│ ├── test_encryption.py
│ ├── test_hashing.py
│ ├── test_file_ops.py
│ └── test_password.py
│
├── sample_files/
│ ├── sample.txt
│ ├── sample.pdf
│ └── image.png
│
├── encrypted_files/ # Ignored by GitHub
└── decrypted_files/ # Ignored by GitHub

> \*\*Note:\*\* `encrypted\_files/` and `decrypted\_files/` are included in `.gitignore` and not pushed to GitHub.

## Installation

1. Clone the repo:
git clone <repo-url>
cd AES_File_Encryption_Tool

2. Install the required library:
pip install -r requirements.txt

Note: Only cryptography is needed. Other modules are built-in Python stuff.

## Usage

- Encrypt a file:
python main.py --encrypt --input sample_files/sample.txt

⦁	Enter your password
⦁	Encrypted file saved in encrypted_files/

- Decrypt a file:
python main.py --decrypt --input encrypted_files/sample.txt.enc

⦁	Enter the same password
⦁	Decrypted file saved in decrypted_files/

## Custom Encrypted File Format

[Salt Length][Salt][IV Length][IV][Ciphertext][Authentication Tag]

⦁	Salt – for key derivation
⦁	IV – for encryption
⦁	Ciphertext – encrypted data
⦁	Tag – to check integrity

--- Decryption reads all of these automatically.

## Testing

Run tests:
pytest tests/

--- Covers: encryption/decryption, key derivation, file reading/writing, password check.

## Limitations

⦁	Must remember password
⦁	CLI only, no GUI
⦁	Only local files, no networking

## Future Improvements

⦁	Add GUI
⦁	Add logging
⦁	Support encryption multiple files or folder

## Author 

Sophat Van