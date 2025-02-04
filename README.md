## File Encryptor

This application is a simple GUI-based file encryptor and decryptor using AES encryption. The program allows you to securely encrypt and decrypt multiple files using a provided key.

### Features
- **File Encryption:** Encrypts selected files with AES encryption.
- **File Decryption:** Decrypts files that were previously encrypted by this tool.
- **Progress Bar:** Displays encryption/decryption progress.
- **Key Management:** Users can input a key for decryption.

### Requirements
- Python 3.x
- Install the required library:
  ```bash
  pip install cryptography
  ```

### Usage

1. **Run the Application:**
   ```bash
   python file_encryptor.py
   ```

2. **Encrypt Files:**
   - Click the **"Encrypt Files"** button.
   - Select the files you want to encrypt.
   - The encryption key is generated automatically and used internally.
   - **Note:** You must save the generated key for decryption purposes.

3. **Decrypt Files:**
   - Enter the encryption key in the "Encryption Key" field (hex format).
   - Click the **"Decrypt Files"** button.
   - Select the encrypted files (`.enc` extension) to decrypt.

### Key Format
- The encryption key is a 256-bit (32-byte) key, displayed as a hexadecimal string.
- Ensure the key is kept safe as it’s required for decrypting files.

### Security Considerations
- The program uses AES encryption with CFB mode for secure file encryption.
- IV (Initialization Vector) is generated randomly for each encryption session.

### Example Key
```
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

### Notes
- The encryption process pads the data to meet AES block size requirements.
- Ensure you enter the correct key for decryption; otherwise, data loss may occur.

### License
This project is licensed under the MIT License.

