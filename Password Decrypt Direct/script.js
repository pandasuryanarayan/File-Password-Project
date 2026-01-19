// Tab Switching
document.querySelectorAll('.tab-btn').forEach(button => {
    button.addEventListener('click', () => {
        const tabName = button.dataset.tab;
        
        // Remove active class from all tabs and contents
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        
        // Add active class to clicked tab and corresponding content
        button.classList.add('active');
        document.getElementById(tabName).classList.add('active');
        
        // Clear messages
        clearMessages();
    });
});

// File Upload - Encrypt
const encryptUploadArea = document.getElementById('encryptUploadArea');
const encryptFileInput = document.getElementById('encryptFileInput');
const encryptFileName = document.getElementById('encryptFileName');

encryptUploadArea.addEventListener('click', () => encryptFileInput.click());

encryptFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        encryptFileName.textContent = `📄 ${file.name} (${formatFileSize(file.size)})`;
    }
});

// Drag and Drop - Encrypt
encryptUploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    encryptUploadArea.classList.add('dragover');
});

encryptUploadArea.addEventListener('dragleave', () => {
    encryptUploadArea.classList.remove('dragover');
});

encryptUploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    encryptUploadArea.classList.remove('dragover');
    
    const file = e.dataTransfer.files[0];
    if (file) {
        encryptFileInput.files = e.dataTransfer.files;
        encryptFileName.textContent = `📄 ${file.name} (${formatFileSize(file.size)})`;
    }
});

// File Upload - Decrypt
const decryptUploadArea = document.getElementById('decryptUploadArea');
const decryptFileInput = document.getElementById('decryptFileInput');
const decryptFileName = document.getElementById('decryptFileName');

decryptUploadArea.addEventListener('click', () => decryptFileInput.click());

decryptFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        decryptFileName.textContent = `📄 ${file.name} (${formatFileSize(file.size)})`;
    }
});

// Drag and Drop - Decrypt
decryptUploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    decryptUploadArea.classList.add('dragover');
});

decryptUploadArea.addEventListener('dragleave', () => {
    decryptUploadArea.classList.remove('dragover');
});

decryptUploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    decryptUploadArea.classList.remove('dragover');
    
    const file = e.dataTransfer.files[0];
    if (file) {
        decryptFileInput.files = e.dataTransfer.files;
        decryptFileName.textContent = `📄 ${file.name} (${formatFileSize(file.size)})`;
    }
});

// Toggle Password Visibility
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    input.type = input.type === 'password' ? 'text' : 'password';
}

// Encrypt Button
document.getElementById('encryptBtn').addEventListener('click', async () => {
    const file = encryptFileInput.files[0];
    const password = document.getElementById('encryptPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const messageEl = document.getElementById('encryptMessage');
    const btn = document.getElementById('encryptBtn');
    
    clearMessages();
    
    // Validation
    if (!file) {
        showMessage(messageEl, 'Please select a file to encrypt', 'error');
        return;
    }
    
    if (!password) {
        showMessage(messageEl, 'Please enter a password', 'error');
        return;
    }
    
    if (password.length < 6) {
        showMessage(messageEl, 'Password must be at least 6 characters long', 'error');
        return;
    }
    
    if (password !== confirmPassword) {
        showMessage(messageEl, 'Passwords do not match', 'error');
        return;
    }
    
    // Show loading state
    setButtonLoading(btn, true);
    
    try {
        const encryptedData = await encryptFile(file, password);
        downloadFile(encryptedData, file.name, 'encrypted');
        showMessage(messageEl, `✅ File encrypted successfully! Download started.`, 'success');
        
        // Reset form
        setTimeout(() => {
            encryptFileInput.value = '';
            encryptFileName.textContent = '';
            document.getElementById('encryptPassword').value = '';
            document.getElementById('confirmPassword').value = '';
        }, 1000);
        
    } catch (error) {
        showMessage(messageEl, `❌ Encryption failed: ${error.message}`, 'error');
    } finally {
        setButtonLoading(btn, false);
    }
});

// Decrypt Button
document.getElementById('decryptBtn').addEventListener('click', async () => {
    const file = decryptFileInput.files[0];
    const password = document.getElementById('decryptPassword').value;
    const messageEl = document.getElementById('decryptMessage');
    const btn = document.getElementById('decryptBtn');
    
    clearMessages();
    
    // Validation
    if (!file) {
        showMessage(messageEl, 'Please select an encrypted file', 'error');
        return;
    }
    
    if (!password) {
        showMessage(messageEl, 'Please enter the password', 'error');
        return;
    }
    
    // Show loading state
    setButtonLoading(btn, true);
    
    try {
        const decryptedData = await decryptFile(file, password);
        const originalFileName = file.name.replace('.encrypted', '');
        downloadFile(decryptedData.data, originalFileName, 'decrypted', decryptedData.type);
        showMessage(messageEl, `✅ File decrypted successfully! Download started.`, 'success');
        
        // Reset form
        setTimeout(() => {
            decryptFileInput.value = '';
            decryptFileName.textContent = '';
            document.getElementById('decryptPassword').value = '';
        }, 1000);
        
    } catch (error) {
        showMessage(messageEl, `❌ Decryption failed: ${error.message}. Wrong password or corrupted file.`, 'error');
    } finally {
        setButtonLoading(btn, false);
    }
});

// Encryption Function using Web Crypto API
async function encryptFile(file, password) {
    const fileData = await file.arrayBuffer();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Derive key from password
    const key = await deriveKey(password, salt);
    
    // Encrypt the file
    const encryptedData = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        fileData
    );
    
    // Store file metadata
    const metadata = {
        originalName: file.name,
        type: file.type,
        size: file.size
    };
    
    const metadataStr = JSON.stringify(metadata);
    const metadataBytes = new TextEncoder().encode(metadataStr);
    const metadataLength = new Uint32Array([metadataBytes.length]);
    
    // Combine: salt + iv + metadataLength + metadata + encrypted data
    const result = new Uint8Array(
        salt.length + 
        iv.length + 
        metadataLength.byteLength + 
        metadataBytes.length + 
        encryptedData.byteLength
    );
    
    let offset = 0;
    result.set(salt, offset);
    offset += salt.length;
    result.set(iv, offset);
    offset += iv.length;
    result.set(new Uint8Array(metadataLength.buffer), offset);
    offset += metadataLength.byteLength;
    result.set(metadataBytes, offset);
    offset += metadataBytes.length;
    result.set(new Uint8Array(encryptedData), offset);
    
    return result;
}

// Decryption Function
async function decryptFile(file, password) {
    const encryptedData = await file.arrayBuffer();
    const dataView = new Uint8Array(encryptedData);
    
    let offset = 0;
    
    // Extract salt
    const salt = dataView.slice(offset, offset + 16);
    offset += 16;
    
    // Extract IV
    const iv = dataView.slice(offset, offset + 12);
    offset += 12;
    
    // Extract metadata length
    const metadataLength = new Uint32Array(dataView.slice(offset, offset + 4).buffer)[0];
    offset += 4;
    
    // Extract metadata
    const metadataBytes = dataView.slice(offset, offset + metadataLength);
    const metadataStr = new TextDecoder().decode(metadataBytes);
    const metadata = JSON.parse(metadataStr);
    offset += metadataLength;
    
    // Extract encrypted content
    const encryptedContent = dataView.slice(offset);
    
    // Derive key from password
    const key = await deriveKey(password, salt);
    
    // Decrypt the file
    const decryptedData = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encryptedContent
    );
    
    return {
        data: decryptedData,
        type: metadata.type,
        name: metadata.originalName
    };
}

// Derive encryption key from password
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    const importedKey = await crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );
    
    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        importedKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

// Download File
function downloadFile(data, fileName, suffix, mimeType = 'application/octet-stream') {
    const blob = new Blob([data], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    
    if (suffix === 'encrypted') {
        a.download = `${fileName}.encrypted`;
    } else {
        a.download = fileName;
    }
    
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Helper Functions
function showMessage(element, message, type) {
    element.textContent = message;
    element.className = `message ${type}`;
}

function clearMessages() {
    document.querySelectorAll('.message').forEach(msg => {
        msg.className = 'message';
        msg.textContent = '';
    });
}

function setButtonLoading(button, isLoading) {
    const btnText = button.querySelector('.btn-text');
    const spinner = button.querySelector('.spinner');
    
    if (isLoading) {
        btnText.style.display = 'none';
        spinner.style.display = 'inline-block';
        button.disabled = true;
    } else {
        btnText.style.display = 'inline';
        spinner.style.display = 'none';
        button.disabled = false;
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}