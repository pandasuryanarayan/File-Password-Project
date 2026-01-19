# File Encryption System

A secure, client-side web application for encrypting and decrypting files directly in your browser. This tool ensures your data remains private by performing all cryptographic operations locally on your device using the Web Crypto API.

## Features

- **Client-Side Security:** Files are encrypted and decrypted locally. No data is ever sent to a server.
- **Strong Encryption:** Uses AES-GCM 256-bit encryption for robust security.
- **Secure Key Derivation:** Derives encryption keys from your password using PBKDF2 with SHA-256 and 100,000 iterations.
- **File Metadata Preservation:** Preserves the original filename and file type within the encrypted file.
- **User-Friendly Interface:**
  - Simple drag-and-drop file upload.
  - distinct tabs for encryption and decryption.
  - Password visibility toggles.
  - Real-time status messages.

## How It Works

### Technical Details

The application utilizes the modern **Web Crypto API** built into your browser:

1.  **Key Generation:** When you enter a password, it is processed through **PBKDF2** (Password-Based Key Derivation Function 2) with a random 16-byte salt, 100,000 iterations, and SHA-256 hashing to generate a secure cryptographic key.
2.  **Encryption:** The file data is encrypted using **AES-GCM** (Advanced Encryption Standard - Galois/Counter Mode) with a 256-bit key and a random 12-byte Initialization Vector (IV).
3.  **File Structure:** The final `.encrypted` file contains:
    - Salt (16 bytes)
    - IV (12 bytes)
    - Metadata Length (4 bytes)
    - Encrypted Metadata (Original filename, type, size)
    - Encrypted File Data

### Usage

#### Running the Tool
Since this is a client-side application, you can simply open the `index.html` file in any modern web browser. No server or installation is required.

#### Encrypting a File
1.  Select the **Encrypt File** tab.
2.  Click the upload area or drag and drop a file.
3.  Enter a strong password (minimum 6 characters).
4.  Confirm the password.
5.  Click **Encrypt & Download**.
6.  The encrypted file will be downloaded with a `.encrypted` extension.

#### Decrypting a File
1.  Select the **Decrypt File** tab.
2.  Upload the `.encrypted` file you previously generated.
3.  Enter the password used for encryption.
4.  Click **Decrypt & Download**.
5.  The file will be decrypted and downloaded with its original name and extension.

## ⚠️ Important Warning

**Do not lose your password!**
Because encryption happens locally and no keys are stored on any server, there is **no way to recover your file** if you forget the password.

## Project Structure

- `index.html`: The main user interface structure.
- `script.js`: Contains all the cryptographic logic (Web Crypto API) and UI handling.
- `style.css`: Styles for the modern, responsive interface.
