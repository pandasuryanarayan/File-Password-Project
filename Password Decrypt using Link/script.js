let selectedFile = null;

// Handle file selection
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        selectedFile = file;
        document.getElementById('fileName').textContent = file.name;
        
        // Show file details
        const fileInfo = document.getElementById('fileInfo');
        const fileSize = formatFileSize(file.size);
        fileInfo.innerHTML = `
            <strong>📄 File:</strong> ${file.name}<br>
            <strong>📦 Size:</strong> ${fileSize}<br>
            <strong>📋 Type:</strong> ${file.type || 'Unknown'}
        `;
        fileInfo.classList.add('active');
        
        // Enable protect button if password is set
        updateProtectButton();
    }
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Update protect button state
function updateProtectButton() {
    const btn = document.getElementById('protectBtn');
    const password = document.getElementById('password').value;
    btn.disabled = !(selectedFile && password.length >= 6);
}

// Password strength checker
document.getElementById('password').addEventListener('input', function(e) {
    const password = e.target.value;
    const strengthBar = document.getElementById('strengthBar');
    
    let strength = 0;
    if (password.length >= 8) strength++;
    if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength++;
    if (password.match(/[0-9]/)) strength++;
    if (password.match(/[^a-zA-Z0-9]/)) strength++;

    strengthBar.className = 'password-strength-bar';
    if (strength <= 1) {
        strengthBar.classList.add('strength-weak');
    } else if (strength <= 3) {
        strengthBar.classList.add('strength-medium');
    } else {
        strengthBar.classList.add('strength-strong');
    }
    
    updateProtectButton();
});

// Show alert message
function showAlert(message, type) {
    const alertBox = document.getElementById('alertBox');
    alertBox.className = 'alert alert-' + type;
    alertBox.textContent = message;
    alertBox.style.display = 'block';
    
    setTimeout(() => {
        alertBox.style.display = 'none';
    }, 5000);
}

// Clear form
function clearForm() {
    selectedFile = null;
    document.getElementById('fileInput').value = '';
    document.getElementById('fileName').textContent = 'No file selected';
    document.getElementById('password').value = '';
    document.getElementById('confirmPassword').value = '';
    document.getElementById('strengthBar').className = 'password-strength-bar';
    document.getElementById('fileInfo').classList.remove('active');
    updateProtectButton();
}

// Read file as ArrayBuffer
function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = (e) => reject(e);
        reader.readAsArrayBuffer(file);
    });
}

// Encrypt data using Web Crypto API
async function encryptData(arrayBuffer, password) {
    const encoder = new TextEncoder();
    
    // Generate a key from password
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );
    
    // Generate salt
    const salt = crypto.getRandomValues(new Uint8Array(16));
    
    // Derive encryption key
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
    
    // Generate IV
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt
    const encryptedData = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        arrayBuffer
    );
    
    // Combine salt + iv + encrypted data
    const combined = new Uint8Array(salt.length + iv.length + encryptedData.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encryptedData), salt.length + iv.length);
    
    // Convert to base64
    return arrayBufferToBase64(combined);
}

// Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Create protected file
async function createProtectedFile() {
    if (!selectedFile) {
        showAlert('Please select a file first', 'error');
        return;
    }

    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    // Validation
    if (!password) {
        showAlert('Please enter a password', 'error');
        return;
    }

    if (password.length < 6) {
        showAlert('Password should be at least 6 characters long', 'error');
        return;
    }

    if (password !== confirmPassword) {
        showAlert('Passwords do not match', 'error');
        return;
    }

    // Show loading
    const btn = document.getElementById('protectBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span>Encrypting...';
    btn.disabled = true;

    try {
        showAlert('Encrypting your file... Please wait.', 'info');
        
        // Read file
        const fileData = await readFileAsArrayBuffer(selectedFile);
        
        // Encrypt the file
        const encryptedData = await encryptData(fileData, password);
        
        // Create the protected HTML file
        const protectedHTML = createProtectedHTML(
            encryptedData,
            selectedFile.name,
            selectedFile.type,
            selectedFile.size
        );
        
        // Download the file
        const protectedFileName = selectedFile.name.split('.')[0] + '_protected.html';
        downloadFile(protectedHTML, protectedFileName);
        
        showAlert('Protected file created successfully!', 'success');
        
        // Reset form after 2 seconds
        setTimeout(clearForm, 2000);
        
    } catch (error) {
        showAlert('Error creating protected file: ' + error.message, 'error');
        console.error(error);
    } finally {
        btn.innerHTML = originalText;
        updateProtectButton();
    }
}

// Create the protected HTML template
function createProtectedHTML(encryptedData, fileName, fileType, fileSize) {
    const escapedFileName = escapeHtml(fileName);
    const formattedSize = formatFileSize(fileSize);
    
    return '<!DOCTYPE html>\n' +
'<html lang="en">\n' +
'<head>\n' +
'    <meta charset="UTF-8">\n' +
'    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
'    <title>🔒 Protected: ' + escapedFileName + '</title>\n' +
'    <style>\n' +
'        * { margin: 0; padding: 0; box-sizing: border-box; }\n' +
'        body {\n' +
'            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;\n' +
'            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n' +
'            min-height: 100vh;\n' +
'            display: flex;\n' +
'            justify-content: center;\n' +
'            align-items: center;\n' +
'            padding: 20px;\n' +
'        }\n' +
'        .container {\n' +
'            background: white;\n' +
'            border-radius: 20px;\n' +
'            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);\n' +
'            max-width: 500px;\n' +
'            width: 100%;\n' +
'            padding: 40px;\n' +
'        }\n' +
'        .lock-icon {\n' +
'            text-align: center;\n' +
'            font-size: 64px;\n' +
'            margin-bottom: 20px;\n' +
'        }\n' +
'        h1 {\n' +
'            color: #333;\n' +
'            text-align: center;\n' +
'            margin-bottom: 10px;\n' +
'            font-size: 24px;\n' +
'        }\n' +
'        .subtitle {\n' +
'            text-align: center;\n' +
'            color: #666;\n' +
'            margin-bottom: 20px;\n' +
'            font-size: 14px;\n' +
'        }\n' +
'        .file-info-box {\n' +
'            background: #f8f9fa;\n' +
'            padding: 15px;\n' +
'            border-radius: 10px;\n' +
'            margin-bottom: 20px;\n' +
'            font-size: 13px;\n' +
'            color: #555;\n' +
'        }\n' +
'        .file-info-box strong { color: #333; }\n' +
'        .input-group { margin-bottom: 20px; }\n' +
'        input[type="password"] {\n' +
'            width: 100%;\n' +
'            padding: 14px 16px;\n' +
'            border: 2px solid #e0e0e0;\n' +
'            border-radius: 10px;\n' +
'            font-size: 16px;\n' +
'            transition: all 0.3s;\n' +
'        }\n' +
'        input[type="password"]:focus {\n' +
'            outline: none;\n' +
'            border-color: #667eea;\n' +
'            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);\n' +
'        }\n' +
'        button {\n' +
'            width: 100%;\n' +
'            padding: 14px 24px;\n' +
'            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n' +
'            color: white;\n' +
'            border: none;\n' +
'            border-radius: 10px;\n' +
'            font-size: 16px;\n' +
'            font-weight: 600;\n' +
'            cursor: pointer;\n' +
'            transition: all 0.3s;\n' +
'            text-transform: uppercase;\n' +
'            letter-spacing: 0.5px;\n' +
'        }\n' +
'        button:hover {\n' +
'            transform: translateY(-2px);\n' +
'            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);\n' +
'        }\n' +
'        .content { display: none; animation: fadeIn 0.5s; }\n' +
'        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }\n' +
'        .error {\n' +
'            color: #f44336;\n' +
'            text-align: center;\n' +
'            margin-top: 10px;\n' +
'            font-size: 14px;\n' +
'            display: none;\n' +
'        }\n' +
'        .success-icon {\n' +
'            text-align: center;\n' +
'            font-size: 64px;\n' +
'            color: #4caf50;\n' +
'            margin-bottom: 20px;\n' +
'        }\n' +
'        .download-btn {\n' +
'            background: #4caf50;\n' +
'            margin-top: 20px;\n' +
'        }\n' +
'        .download-btn:hover {\n' +
'            background: #45a049;\n' +
'        }\n' +
'    </style>\n' +
'</head>\n' +
'<body>\n' +
'    <div class="container">\n' +
'        <div id="loginForm">\n' +
'            <div class="lock-icon">🔒</div>\n' +
'            <h1>Protected File</h1>\n' +
'            <p class="subtitle">This file is password protected</p>\n' +
'            <div class="file-info-box">\n' +
'                <strong>📄 File:</strong> ' + escapedFileName + '<br>\n' +
'                <strong>📦 Size:</strong> ' + formattedSize + '\n' +
'            </div>\n' +
'            <div class="input-group">\n' +
'                <input type="password" id="passwordInput" placeholder="Enter password" onkeypress="if(event.key===\'Enter\') unlock()">\n' +
'            </div>\n' +
'            <button onclick="unlock()">Unlock File</button>\n' +
'            <div id="error" class="error">Incorrect password. Please try again.</div>\n' +
'        </div>\n' +
'        <div id="content" class="content">\n' +
'            <div class="success-icon">✓</div>\n' +
'            <h1>File Unlocked!</h1>\n' +
'            <p class="subtitle">Your file is ready to download</p>\n' +
'            <div class="file-info-box">\n' +
'                <strong>📄 File:</strong> ' + escapedFileName + '<br>\n' +
'                <strong>📦 Size:</strong> ' + formattedSize + '\n' +
'            </div>\n' +
'            <button class="download-btn" onclick="downloadDecryptedFile()">⬇️ Download File</button>\n' +
'        </div>\n' +
'    </div>\n' +
'    <script>\n' +
'        const encryptedData = "' + encryptedData + '";\n' +
'        const originalFileName = "' + escapedFileName + '";\n' +
'        const originalFileType = "' + fileType + '";\n' +
'        let decryptedBlob = null;\n' +
'        \n' +
'        async function unlock() {\n' +
'            const password = document.getElementById("passwordInput").value;\n' +
'            const errorDiv = document.getElementById("error");\n' +
'            \n' +
'            if (!password) {\n' +
'                errorDiv.style.display = "block";\n' +
'                errorDiv.textContent = "Please enter a password";\n' +
'                return;\n' +
'            }\n' +
'            \n' +
'            try {\n' +
'                const decrypted = await decryptData(encryptedData, password);\n' +
'                decryptedBlob = new Blob([decrypted], { type: originalFileType });\n' +
'                document.getElementById("loginForm").style.display = "none";\n' +
'                document.getElementById("content").style.display = "block";\n' +
'            } catch (error) {\n' +
'                errorDiv.style.display = "block";\n' +
'                errorDiv.textContent = "Incorrect password. Please try again.";\n' +
'                document.getElementById("passwordInput").value = "";\n' +
'                document.getElementById("passwordInput").focus();\n' +
'            }\n' +
'        }\n' +
'        \n' +
'        function downloadDecryptedFile() {\n' +
'            if (!decryptedBlob) return;\n' +
'            const url = URL.createObjectURL(decryptedBlob);\n' +
'            const a = document.createElement("a");\n' +
'            a.href = url;\n' +
'            a.download = originalFileName;\n' +
'            document.body.appendChild(a);\n' +
'            a.click();\n' +
'            document.body.removeChild(a);\n' +
'            URL.revokeObjectURL(url);\n' +
'        }\n' +
'        \n' +
'        function base64ToArrayBuffer(base64) {\n' +
'            const binaryString = atob(base64);\n' +
'            const bytes = new Uint8Array(binaryString.length);\n' +
'            for (let i = 0; i < binaryString.length; i++) {\n' +
'                bytes[i] = binaryString.charCodeAt(i);\n' +
'            }\n' +
'            return bytes.buffer;\n' +
'        }\n' +
'        \n' +
'        async function decryptData(encryptedBase64, password) {\n' +
'            const encoder = new TextEncoder();\n' +
'            const encryptedArray = new Uint8Array(base64ToArrayBuffer(encryptedBase64));\n' +
'            \n' +
'            const salt = encryptedArray.slice(0, 16);\n' +
'            const iv = encryptedArray.slice(16, 28);\n' +
'            const data = encryptedArray.slice(28);\n' +
'            \n' +
'            const passwordKey = await crypto.subtle.importKey(\n' +
'                "raw",\n' +
'                encoder.encode(password),\n' +
'                "PBKDF2",\n' +
'                false,\n' +
'                ["deriveBits", "deriveKey"]\n' +
'            );\n' +
'            \n' +
'            const key = await crypto.subtle.deriveKey(\n' +
'                {\n' +
'                    name: "PBKDF2",\n' +
'                    salt: salt,\n' +
'                    iterations: 100000,\n' +
'                    hash: "SHA-256"\n' +
'                },\n' +
'                passwordKey,\n' +
'                { name: "AES-GCM", length: 256 },\n' +
'                false,\n' +
'                ["decrypt"]\n' +
'            );\n' +
'            \n' +
'            const decryptedData = await crypto.subtle.decrypt(\n' +
'                { name: "AES-GCM", iv: iv },\n' +
'                key,\n' +
'                data\n' +
'            );\n' +
'            \n' +
'            return decryptedData;\n' +
'        }\n' +
'        \n' +
'        document.getElementById("passwordInput").focus();\n' +
'    </script>\n' +
'</body>\n' +
'</html>';
}

// Helper function to escape HTML
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

// Download file
function downloadFile(content, filename) {
    const blob = new Blob([content], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}