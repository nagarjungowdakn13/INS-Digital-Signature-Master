/**
 * Digital Signature Tool - Frontend JavaScript
 * Handles all UI interactions and API calls
 */

// ====================================
// State Management
// ====================================
const state = {
    keysExist: false,
    signFile: null,
    verifyFile: null,
    verifySigFile: null,
    lastSignatureData: null
};

// ====================================
// DOM Elements
// ====================================
const elements = {
    // Status
    statusIndicator: document.getElementById('statusIndicator'),
    statusText: document.getElementById('statusText'),
    keyStatusBox: document.getElementById('keyStatusBox'),
    keyIcon: document.getElementById('keyIcon'),
    keyTitle: document.getElementById('keyTitle'),
    keyDescription: document.getElementById('keyDescription'),
    
    // Tabs
    tabsContainer: document.getElementById('tabs'),
    tabIndicator: document.getElementById('tabIndicator'),
    tabs: document.querySelectorAll('.tab'),
    tabPanes: document.querySelectorAll('.tab-pane'),
    
    // Key Generation
    generateKeysBtn: document.getElementById('generateKeysBtn'),
    
    // Sign File
    signUploadZone: document.getElementById('signUploadZone'),
    signFileInput: document.getElementById('signFileInput'),
    signSelectedFile: document.getElementById('signSelectedFile'),
    signFileName: document.getElementById('signFileName'),
    signFileSize: document.getElementById('signFileSize'),
    removeSignFile: document.getElementById('removeSignFile'),
    signFileBtn: document.getElementById('signFileBtn'),
    signResult: document.getElementById('signResult'),
    resultSignFileName: document.getElementById('resultSignFileName'),
    resultSignHash: document.getElementById('resultSignHash'),
    resultSignTime: document.getElementById('resultSignTime'),
    downloadSigBtn: document.getElementById('downloadSigBtn'),
    copySigBtn: document.getElementById('copySigBtn'),
    signatureJson: document.getElementById('signatureJson'),
    
    // Verify File
    verifyFileZone: document.getElementById('verifyFileZone'),
    verifyFileInput: document.getElementById('verifyFileInput'),
    verifySelectedFile: document.getElementById('verifySelectedFile'),
    verifyFileName: document.getElementById('verifyFileName'),
    verifyFileSize: document.getElementById('verifyFileSize'),
    removeVerifyFile: document.getElementById('removeVerifyFile'),
    verifySigZone: document.getElementById('verifySigZone'),
    verifySigInput: document.getElementById('verifySigInput'),
    verifySelectedSig: document.getElementById('verifySelectedSig'),
    verifySigName: document.getElementById('verifySigName'),
    verifySigSize: document.getElementById('verifySigSize'),
    removeVerifySig: document.getElementById('removeVerifySig'),
    signatureTextarea: document.getElementById('signatureTextarea'),
    verifyBtn: document.getElementById('verifyBtn'),
    verifyResult: document.getElementById('verifyResult'),
    verifyResultHeader: document.getElementById('verifyResultHeader'),
    verifyResultTitle: document.getElementById('verifyResultTitle'),
    verificationBadge: document.getElementById('verificationBadge'),
    resultVerifyFileName: document.getElementById('resultVerifyFileName'),
    resultVerifyCalcHash: document.getElementById('resultVerifyCalcHash'),
    resultVerifyOrigHash: document.getElementById('resultVerifyOrigHash'),
    resultVerifyAlgo: document.getElementById('resultVerifyAlgo'),
    resultVerifyTime: document.getElementById('resultVerifyTime'),
    
    // Sign Text
    textMessage: document.getElementById('textMessage'),
    signTextBtn: document.getElementById('signTextBtn'),
    textSignProcess: document.getElementById('textSignProcess'),
    textOriginalMsg: document.getElementById('textOriginalMsg'),
    textBobHash: document.getElementById('textBobHash'),
    textSignature: document.getElementById('textSignature'),
    textAliceHash: document.getElementById('textAliceHash'),
    textDecryptedHash: document.getElementById('textDecryptedHash'),
    textVerificationStatus: document.getElementById('textVerificationStatus'),
    
    // Loading & Toast
    loadingOverlay: document.getElementById('loadingOverlay'),
    loadingText: document.getElementById('loadingText'),
    toastContainer: document.getElementById('toastContainer')
};

// ====================================
// Utility Functions
// ====================================

const CHECK_MARK = '<svg class="mark" viewBox="0 0 24 24"><path d="M4 12.5l5 5L20 6"/></svg>';
const CROSS_MARK = '<svg class="mark" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>';

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showLoading(text = 'Processing...') {
    elements.loadingText.textContent = text;
    elements.loadingOverlay.classList.remove('hidden');
}

function hideLoading() {
    elements.loadingOverlay.classList.add('hidden');
}

function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle'
    };
    
    toast.innerHTML = `
        <i class="fas ${icons[type]}"></i>
        <span class="toast-message">${message}</span>
    `;
    
    elements.toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ====================================
// API Functions
// ====================================

async function checkStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        state.keysExist = data.keys_exist;
        updateKeyStatus(data);
    } catch (error) {
        console.error('Error checking status:', error);
        showToast('Error connecting to server', 'error');
    }
}

async function generateKeys() {
    const keySize = document.querySelector('input[name="keySize"]:checked').value;
    
    showLoading(`Generating ${keySize}-bit RSA keys...`);
    
    try {
        const response = await fetch('/api/generate-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key_size: parseInt(keySize) })
        });
        
        const data = await response.json();
        
        if (data.success) {
            state.keysExist = true;
            showToast(data.message, 'success');
            await checkStatus();
        } else {
            showToast(data.error, 'error');
        }
    } catch (error) {
        console.error('Error generating keys:', error);
        showToast('Error generating keys', 'error');
    } finally {
        hideLoading();
    }
}

async function signFile() {
    if (!state.signFile) {
        showToast('Please select a file to sign', 'warning');
        return;
    }
    
    if (!state.keysExist) {
        showToast('Please generate keys first', 'warning');
        return;
    }
    
    showLoading('Signing file...');
    
    try {
        const formData = new FormData();
        formData.append('file', state.signFile);
        
        const response = await fetch('/api/sign-file', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            state.lastSignatureData = data.signature_data;
            displaySignResult(data);
            showToast('File signed successfully!', 'success');
        } else {
            showToast(data.error, 'error');
        }
    } catch (error) {
        console.error('Error signing file:', error);
        showToast('Error signing file', 'error');
    } finally {
        hideLoading();
    }
}

async function verifyFile() {
    if (!state.verifyFile) {
        showToast('Please select a file to verify', 'warning');
        return;
    }
    
    const signatureJson = elements.signatureTextarea.value.trim();
    
    if (!state.verifySigFile && !signatureJson) {
        showToast('Please provide a signature', 'warning');
        return;
    }
    
    if (!state.keysExist) {
        showToast('Please generate keys first', 'warning');
        return;
    }
    
    showLoading('Verifying signature...');
    
    try {
        const formData = new FormData();
        formData.append('file', state.verifyFile);
        
        if (state.verifySigFile) {
            formData.append('signature_file', state.verifySigFile);
        } else {
            formData.append('signature', signatureJson);
        }
        
        const response = await fetch('/api/verify-file', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success !== undefined) {
            displayVerifyResult(data);
            showToast(data.is_valid ? 'Signature verified!' : 'Invalid signature!', 
                      data.is_valid ? 'success' : 'error');
        } else {
            showToast(data.error, 'error');
        }
    } catch (error) {
        console.error('Error verifying file:', error);
        showToast('Error verifying file', 'error');
    } finally {
        hideLoading();
    }
}

async function signText() {
    const message = elements.textMessage.value.trim();
    
    if (!message) {
        showToast('Please enter a message to sign', 'warning');
        return;
    }
    
    showLoading('Signing message...');
    
    try {
        const response = await fetch('/api/sign-text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayTextSignResult(data);
            showToast('Message signed and verified!', 'success');
        } else {
            showToast(data.error, 'error');
        }
    } catch (error) {
        console.error('Error signing text:', error);
        showToast('Error signing text', 'error');
    } finally {
        hideLoading();
    }
}

// ====================================
// UI Update Functions
// ====================================

function updateKeyStatus(data) {
    if (data.keys_exist) {
        elements.statusIndicator.className = 'status-indicator active';
        elements.statusText.textContent = `Keys Ready (${data.key_info?.key_size || 1024}-bit)`;
        
        elements.keyStatusBox.classList.add('active');
        elements.keyIcon.className = 'fas fa-unlock';
        elements.keyTitle.textContent = 'Keys Available';
        elements.keyDescription.textContent = `${data.key_info?.key_size || 1024}-bit RSA key pair is ready for use`;
    } else {
        elements.statusIndicator.className = 'status-indicator inactive';
        elements.statusText.textContent = 'No Keys';
        
        elements.keyStatusBox.classList.remove('active');
        elements.keyIcon.className = 'fas fa-lock';
        elements.keyTitle.textContent = 'No Keys Found';
        elements.keyDescription.textContent = 'Generate a new RSA key pair to start signing files';
    }
    
    updateButtonStates();
}

function updateButtonStates() {
    // Sign file button
    elements.signFileBtn.disabled = !state.signFile || !state.keysExist;
    
    // Verify button
    const hasSignature = state.verifySigFile || elements.signatureTextarea.value.trim();
    elements.verifyBtn.disabled = !state.verifyFile || !hasSignature || !state.keysExist;
}

function displaySignResult(data) {
    elements.resultSignFileName.textContent = data.filename;
    elements.resultSignHash.textContent = data.hash;
    elements.resultSignTime.textContent = new Date(data.signature_data.timestamp).toLocaleString();
    elements.signatureJson.textContent = data.signature_json;
    
    elements.signResult.classList.remove('hidden');
}

function displayVerifyResult(data) {
    const isValid = data.is_valid;
    
    elements.verifyResultHeader.className = `result-header ${isValid ? 'success' : 'error'}`;
    elements.verifyResultHeader.innerHTML = `
        <i class="fas fa-${isValid ? 'check' : 'times'}-circle"></i>
        <span>${isValid ? 'Signature Valid!' : 'Signature Invalid!'}</span>
    `;
    
    elements.verificationBadge.className = `verification-badge ${isValid ? 'valid' : 'invalid'}`;
    elements.verificationBadge.innerHTML = `
        ${isValid ? CHECK_MARK : CROSS_MARK}
        <span>${isValid ? 'VALID' : 'INVALID'}</span>
    `;
    
    elements.resultVerifyFileName.textContent = data.filename;
    elements.resultVerifyCalcHash.textContent = data.calculated_hash;
    elements.resultVerifyOrigHash.textContent = data.original_hash;
    elements.resultVerifyAlgo.textContent = data.algorithm;
    elements.resultVerifyTime.textContent = data.signed_on !== 'Unknown' 
        ? new Date(data.signed_on).toLocaleString() 
        : 'Unknown';
    
    elements.verifyResult.classList.remove('hidden');
}

function displayTextSignResult(data) {
    elements.textOriginalMsg.textContent = data.signing.message;
    elements.textBobHash.textContent = data.signing.hash;
    elements.textSignature.textContent = data.signing.signature;
    elements.textAliceHash.textContent = data.verification.calculated_hash;
    elements.textDecryptedHash.textContent = data.verification.decrypted_hash;
    
    const isValid = data.verification.is_valid;
    elements.textVerificationStatus.className = `verification-status ${isValid ? '' : 'invalid'}`;
    elements.textVerificationStatus.innerHTML = `
        <i class="fas fa-${isValid ? 'check' : 'times'}-circle"></i>
        <span>${isValid ? 'Hashes match! Message is authentic.' : 'Hashes do not match! Message may be tampered.'}</span>
    `;
    
    elements.textSignProcess.classList.remove('hidden');
}

// ====================================
// Event Handlers
// ====================================

function moveTabIndicator(tab) {
    if (!elements.tabIndicator || !tab) return;
    // The indicator's CSS resting position already sits at the container's
    // left padding, matching where offsetLeft starts counting from.
    const containerPadding = parseFloat(getComputedStyle(elements.tabsContainer).paddingLeft) || 0;
    elements.tabIndicator.style.width = `${tab.offsetWidth}px`;
    elements.tabIndicator.style.transform = `translateX(${tab.offsetLeft - containerPadding}px)`;
}

function setupTabs() {
    elements.tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetId = tab.dataset.tab;

            // Update tabs
            elements.tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            moveTabIndicator(tab);

            // Update panes
            elements.tabPanes.forEach(pane => {
                pane.classList.remove('active');
                if (pane.id === targetId) {
                    pane.classList.add('active');
                }
            });
        });
    });

    // Position the indicator under the initially active tab
    const activeTab = document.querySelector('.tab.active') || elements.tabs[0];
    requestAnimationFrame(() => moveTabIndicator(activeTab));

    window.addEventListener('resize', () => {
        const current = document.querySelector('.tab.active');
        moveTabIndicator(current);
    });
}

function setupButtonRipples() {
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.btn');
        if (!btn || btn.disabled) return;

        const rect = btn.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height) * 1.6;
        const ripple = document.createElement('span');
        ripple.className = 'ink-ripple';
        ripple.style.width = ripple.style.height = `${size}px`;
        ripple.style.left = `${e.clientX - rect.left - size / 2}px`;
        ripple.style.top = `${e.clientY - rect.top - size / 2}px`;

        btn.appendChild(ripple);
        ripple.addEventListener('animationend', () => ripple.remove());
    });
}

function setupFileUpload(zone, input, selectedDiv, nameEl, sizeEl, removeBtn, stateKey) {
    // Click to upload
    zone.addEventListener('click', () => input.click());
    
    // Drag and drop
    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
    });
    
    zone.addEventListener('dragleave', () => {
        zone.classList.remove('dragover');
    });
    
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelect(files[0], zone, selectedDiv, nameEl, sizeEl, stateKey);
        }
    });
    
    // File input change
    input.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files[0], zone, selectedDiv, nameEl, sizeEl, stateKey);
        }
    });
    
    // Remove file
    removeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        state[stateKey] = null;
        input.value = '';
        zone.classList.remove('hidden');
        selectedDiv.classList.add('hidden');
        updateButtonStates();
    });
}

function handleFileSelect(file, zone, selectedDiv, nameEl, sizeEl, stateKey) {
    state[stateKey] = file;
    nameEl.textContent = file.name;
    sizeEl.textContent = formatFileSize(file.size);
    zone.classList.add('hidden');
    selectedDiv.classList.remove('hidden');
    updateButtonStates();
}

function setupEventListeners() {
    // Generate keys
    elements.generateKeysBtn.addEventListener('click', generateKeys);
    
    // Sign file
    setupFileUpload(
        elements.signUploadZone,
        elements.signFileInput,
        elements.signSelectedFile,
        elements.signFileName,
        elements.signFileSize,
        elements.removeSignFile,
        'signFile'
    );
    elements.signFileBtn.addEventListener('click', signFile);
    
    // Download signature
    elements.downloadSigBtn.addEventListener('click', () => {
        if (!state.lastSignatureData) return;
        
        const blob = new Blob([JSON.stringify(state.lastSignatureData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = (state.lastSignatureData.original_filename || 'signature') + '.sig';
        a.click();
        URL.revokeObjectURL(url);
        showToast('Signature downloaded!', 'success');
    });
    
    // Copy signature
    elements.copySigBtn.addEventListener('click', () => {
        if (!state.lastSignatureData) return;
        
        navigator.clipboard.writeText(JSON.stringify(state.lastSignatureData, null, 2))
            .then(() => showToast('Signature copied to clipboard!', 'success'))
            .catch(() => showToast('Failed to copy', 'error'));
    });
    
    // Verify file
    setupFileUpload(
        elements.verifyFileZone,
        elements.verifyFileInput,
        elements.verifySelectedFile,
        elements.verifyFileName,
        elements.verifyFileSize,
        elements.removeVerifyFile,
        'verifyFile'
    );
    
    // Verify signature file
    setupFileUpload(
        elements.verifySigZone,
        elements.verifySigInput,
        elements.verifySelectedSig,
        elements.verifySigName,
        elements.verifySigSize,
        elements.removeVerifySig,
        'verifySigFile'
    );
    
    elements.signatureTextarea.addEventListener('input', updateButtonStates);
    elements.verifyBtn.addEventListener('click', verifyFile);
    
    // Sign text
    elements.signTextBtn.addEventListener('click', signText);
}

// ====================================
// Initialization
// ====================================

document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    setupEventListeners();
    setupButtonRipples();
    checkStatus();
});
