# File Password Protection Tools

This repository contains two distinct client-side web applications for encrypting and protecting files using the Web Crypto API. Both tools operate entirely within the browser, ensuring that your files and passwords never leave your device.

## Projects Overview

1.  **Password Decrypt Direct**: A direct encryption/decryption tool that generates a `.encrypted` file.
2.  **Password Decrypt using Link (File Password Protector)**: A tool that wraps your file into a self-extracting, password-protected HTML file.

---

## 1. Password Decrypt Direct

This tool allows you to encrypt any file into a proprietary `.encrypted` format and decrypt it back using the same tool.

### Features
*   **Secure Encryption**: Uses AES-GCM 256-bit encryption.
*   **Client-Side Processing**: Files are processed locally; no server uploads.
*   **Custom Format**: Generates `.encrypted` files containing salt, IV, metadata, and encrypted content.
*   **Metadata Preservation**: Preserves the original filename and file type.

### How to Use
1.  **Encrypt**:
    *   Open `index.html` in the `Password Decrypt Direct/` folder.
    *   Select the "Encrypt File" tab.
    *   Upload or drag & drop your file.
    *   Set a password and confirm it.
    *   Click "Encrypt & Download".
    *   A `.encrypted` file will be downloaded.
2.  **Decrypt**:
    *   Select the "Decrypt File" tab.
    *   Upload the `.encrypted` file.
    *   Enter the password used for encryption.
    *   Click "Decrypt & Download" to retrieve the original file.

### Technical Details
*   **Key Derivation**: PBKDF2 with SHA-256 and 100,000 iterations.
*   **Encryption**: AES-GCM (Galois/Counter Mode) with a 256-bit key.
*   **Structure**: The output file is a binary concatenation of: `Salt (16 bytes) | IV (12 bytes) | Metadata Length (4 bytes) | Metadata (JSON) | Encrypted Data`.

---

## 2. Password Decrypt using Link (File Password Protector)

This tool creates a portable, self-contained HTML file containing your encrypted data. You can send this HTML file to anyone, and they can decrypt and access the file using only a web browser and the correct password.

### Features
*   **Portable**: The output is a standard HTML file. No special software is needed to decrypt.
*   **Self-Extracting**: The decryption logic is embedded within the HTML file.
*   **Cross-Platform**: Works on any device with a modern web browser (Windows, Mac, Linux, Android, iOS).
*   **Secure**: Uses the same robust AES-GCM encryption.

### How to Use
1.  **Protect a File**:
    *   Open `password-protector.html` in the `Password Decrypt using Link/` folder.
    *   Select the file you want to protect.
    *   Set a strong password.
    *   Click "Protect File".
    *   A new file ending in `_protected.html` will be downloaded.
2.  **Open a Protected File**:
    *   Open the `_protected.html` file in any web browser.
    *   Enter the password.
    *   Upon success, the original file will be unlocked and ready for download.

### Technical Details
*   **Embedding**: The encrypted file data is Base64 encoded and embedded directly into the JavaScript of the generated HTML file.
*   **Decryption**: The generated HTML contains a mini-app that handles the password input, key derivation (PBKDF2), and decryption (AES-GCM) locally.

---

## Security Note

*   **No Password Recovery**: Since these tools do not store your password anywhere (locally or on a server), if you forget your password, the encrypted files **cannot be recovered**.
*   **Browser Support**: Requires a modern browser with support for the Web Crypto API (Chrome, Firefox, Safari, Edge).
