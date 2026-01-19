# Password Decrypt using Link (Password Protector)

This tool allows you to securely encrypt any file (images, documents, PDFs, videos, etc.) and convert it into a self-extracting HTML file. The protected file can be safely shared via email, cloud storage, or any other medium. To access the original file, the recipient simply needs to open the HTML file in a web browser and enter the correct password.

## Features

*   **Universal Compatibility**: Works on any device with a modern web browser (Windows, Mac, Linux, iOS, Android).
*   **Zero Dependencies**: The output is a single, self-contained HTML file. No external software or plugins are required to decrypt.
*   **Client-Side Encryption**: All encryption and decryption happen entirely within your browser. Your files are never uploaded to any server, ensuring complete privacy.
*   **Strong Security**: Uses industry-standard cryptographic algorithms (AES-256-GCM and PBKDF2).

## How It Works

1.  **Select File**: You choose a file from your device.
2.  **Encrypt**: The tool generates a unique encryption key from your password using **PBKDF2** (SHA-256, 100,000 iterations). It then encrypts the file content using **AES-256-GCM**.
3.  **Package**: The encrypted data (Base64 encoded), along with the decryption logic, is embedded into a new HTML file.
4.  **Decrypt**: When the HTML file is opened, it prompts for the password. It derives the key again and decrypts the data in the browser, allowing you to download the original file.

## Usage

### To Protect a File:

1.  Open `password-protector.html` in your web browser.
2.  Click "Select File to Protect" or drag and drop a file.
3.  Enter a strong password in the "Set Password" field.
4.  Re-enter the password in the "Confirm Password" field.
5.  Click the "Protect File" button.
6.  A new file named `Protected-[original_filename].html` will be downloaded to your device.

### To Open a Protected File:

1.  Double-click the downloaded HTML file to open it in your default web browser.
2.  Enter the password you set during encryption.
3.  Click "Unlock File".
4.  Once unlocked, click "Download File" to save the original decrypted file to your device.

## Technical Details

*   **Encryption Algorithm**: AES-GCM (Galois/Counter Mode) with a 256-bit key.
*   **Key Derivation**: PBKDF2 (Password-Based Key Derivation Function 2) using SHA-256 and 100,000 iterations.
*   **Salt & IV**: A random 16-byte salt is used for key derivation, and a random 12-byte IV (Initialization Vector) is used for encryption. These are stored alongside the encrypted data.
*   **Implementation**: Built using the standard Web Crypto API available in all modern browsers.

## Files in this Directory

*   `password-protector.html`: The main interface for encrypting files.
*   `script.js`: Handles the file processing, encryption logic, and HTML generation.
*   `style.css`: Contains the styling for the user interface.
