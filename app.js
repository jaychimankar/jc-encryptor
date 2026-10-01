/**
 * CipherVault Studio - Main UI Controller & Event Handlers
 */

document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    // --- Global Elements & State ---
    const toastContainer = document.getElementById('toast-container');
    let currentStegoCanvasData = null;

    // Helper: Toast Notifications
    function showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        let icon = 'ℹ️';
        if (type === 'success') icon = '✅';
        if (type === 'warning') icon = '⚠️';

        toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // --- Tab Navigation Controller ---
    const tabButtons = document.querySelectorAll('#main-tabs .tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');

            tabButtons.forEach(b => b.classList.remove('active'));
            tabPanels.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(targetTab).classList.add('active');
        });
    });

    // --- Clear Workspace Action ---
    document.getElementById('btn-clear-all').addEventListener('click', () => {
        document.querySelectorAll('textarea, input[type="text"], input[type="password"]').forEach(el => el.value = '');
        document.querySelectorAll('.output-box').forEach(el => el.textContent = '-');
        showToast('Workspace inputs cleared successfully!', 'info');
    });

    // --- TAB 1: Symmetric AES Encryption ---
    const aesInput = document.getElementById('aes-input');
    const aesPassphrase = document.getElementById('aes-passphrase');
    const aesOutput = document.getElementById('aes-output');
    const inspectSalt = document.getElementById('inspect-salt');
    const inspectIv = document.getElementById('inspect-iv');
    const aesStatusTag = document.getElementById('aes-status-tag');

    let currentAESData = null;

    document.getElementById('btn-aes-encrypt').addEventListener('click', async () => {
        const text = aesInput.value;
        const passphrase = aesPassphrase.value;
        const mode = document.querySelector('input[name="aes-mode"]:checked').value;

        if (!text) return showToast('Please enter plaintext payload to encrypt!', 'warning');
        if (!passphrase) return showToast('Please enter a secret passphrase!', 'warning');

        try {
            aesStatusTag.textContent = 'Encrypting...';
            const result = await CryptoEngine.encryptAES(passphrase, text, mode);
            currentAESData = result;

            aesOutput.textContent = result.ciphertextBase64;
            inspectSalt.textContent = result.saltHex;
            inspectIv.textContent = result.ivHex;
            aesStatusTag.textContent = 'AES Encrypted';
            showToast('AES encryption completed successfully!', 'success');
        } catch (e) {
            showToast(e.message, 'warning');
            aesStatusTag.textContent = 'Error';
        }
    });

    document.getElementById('btn-aes-decrypt').addEventListener('click', async () => {
        const cipherText = aesInput.value.trim() || (currentAESData ? currentAESData.ciphertextBase64 : '');
        const passphrase = aesPassphrase.value;
        const mode = document.querySelector('input[name="aes-mode"]:checked').value;

        if (!cipherText) return showToast('Please paste ciphertext or encrypt text first!', 'warning');
        if (!passphrase) return showToast('Please enter secret passphrase for decryption!', 'warning');

        let saltHex = inspectSalt.textContent !== '-' ? inspectSalt.textContent : '';
        let ivHex = inspectIv.textContent !== '-' ? inspectIv.textContent : '';

        if (!saltHex || !ivHex) {
            // If user pasted raw ciphertext, prompt or use default state
            saltHex = currentAESData ? currentAESData.saltHex : '';
            ivHex = currentAESData ? currentAESData.ivHex : '';
        }

        try {
            aesStatusTag.textContent = 'Decrypting...';
            const decrypted = await CryptoEngine.decryptAES(passphrase, cipherText, saltHex, ivHex, mode);
            aesOutput.textContent = decrypted;
            aesStatusTag.textContent = 'Decrypted';
            showToast('Decryption successful!', 'success');
        } catch (e) {
            showToast(e.message, 'warning');
            aesStatusTag.textContent = 'Decryption Failed';
        }
    });

    // AES Copy & Download Actions
    document.getElementById('btn-aes-copy').addEventListener('click', () => {
        const text = aesOutput.textContent;
        if (text && text !== '-') {
            navigator.clipboard.writeText(text);
            showToast('Copied to clipboard!', 'success');
        }
    });

    document.getElementById('btn-aes-download').addEventListener('click', () => {
        const text = aesOutput.textContent;
        if (text && text !== '-') {
            const blob = new Blob([text], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'encrypted_vault.txt';
            a.click();
            URL.revokeObjectURL(url);
        }
    });

    // AES File Drop for .enc Container
    const aesFileDrop = document.getElementById('aes-file-drop');
    const aesFileInput = document.getElementById('aes-file-input');

    aesFileDrop.addEventListener('click', () => aesFileInput.click());
    aesFileDrop.addEventListener('dragover', (e) => { e.preventDefault(); aesFileDrop.classList.add('dragover'); });
    aesFileDrop.addEventListener('dragleave', () => aesFileDrop.classList.remove('dragover'));
    aesFileDrop.addEventListener('drop', async (e) => {
        e.preventDefault();
        aesFileDrop.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            processAESFile(e.dataTransfer.files[0]);
        }
    });

    aesFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) processAESFile(e.target.files[0]);
    });

    async function processAESFile(file) {
        const passphrase = aesPassphrase.value;
        if (!passphrase) return showToast('Please set a passphrase before dropping file!', 'warning');

        const reader = new FileReader();
        reader.onload = async (evt) => {
            const arrayBuf = evt.target.result;
            if (file.name.endsWith('.enc')) {
                // Unpack & Decrypt .enc
                try {
                    const decryptedBuf = await CryptoEngine.unpackEncryptedFile(new Uint8Array(arrayBuf), passphrase);
                    const blob = new Blob([decryptedBuf]);
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = file.name.replace('.enc', '_decrypted');
                    a.click();
                    showToast(`File decrypted and downloaded: ${a.download}`, 'success');
                } catch (err) {
                    showToast(err.message, 'warning');
                }
            } else {
                // Pack & Encrypt to .enc
                const encPacked = await CryptoEngine.packEncryptedFile(arrayBuf, passphrase);
                const blob = new Blob([encPacked], { type: 'application/octet-stream' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${file.name}.enc`;
                a.click();
                showToast(`Secure .enc container created for ${file.name}!`, 'success');
            }
        };
        reader.readAsArrayBuffer(file);
    }

    // --- TAB 2: Asymmetric RSA Keypair & Encryption ---
    const rsaPub = document.getElementById('rsa-pubkey');
    const rsaPriv = document.getElementById('rsa-privkey');
    const rsaInput = document.getElementById('rsa-input');
    const rsaOutput = document.getElementById('rsa-output');

    document.getElementById('btn-rsa-generate').addEventListener('click', async () => {
        const modulus = document.querySelector('input[name="rsa-modulus"]:checked').value;
        showToast(`Generating ${modulus}-bit RSA Key Pair...`, 'info');

        try {
            const keys = await CryptoEngine.generateRSAKeyPair(modulus);
            rsaPub.value = keys.publicKeyPEM;
            rsaPriv.value = keys.privateKeyPEM;
            showToast(`${modulus}-bit RSA Key Pair generated!`, 'success');
        } catch (err) {
            showToast(err.message, 'warning');
        }
    });

    document.getElementById('btn-rsa-encrypt').addEventListener('click', async () => {
        const pubPEM = rsaPub.value.trim();
        const text = rsaInput.value;
        if (!pubPEM) return showToast('Public Key required for RSA encryption!', 'warning');
        if (!text) return showToast('Enter text payload to encrypt!', 'warning');

        try {
            const encryptedB64 = await CryptoEngine.encryptRSA(pubPEM, text);
            rsaOutput.textContent = encryptedB64;
            showToast('RSA Public Key Encryption complete!', 'success');
        } catch (err) {
            showToast(err.message, 'warning');
        }
    });

    document.getElementById('btn-rsa-decrypt').addEventListener('click', async () => {
        const privPEM = rsaPriv.value.trim();
        const cipherB64 = rsaInput.value.trim() || rsaOutput.textContent;
        if (!privPEM) return showToast('Private Key required for RSA decryption!', 'warning');
        if (!cipherB64 || cipherB64 === '-') return showToast('Enter or generate RSA ciphertext to decrypt!', 'warning');

        try {
            const decryptedText = await CryptoEngine.decryptRSA(privPEM, cipherB64);
            rsaOutput.textContent = decryptedText;
            showToast('RSA Decryption complete!', 'success');
        } catch (err) {
            showToast(err.message, 'warning');
        }
    });

    document.getElementById('btn-rsa-copy').addEventListener('click', () => {
        if (rsaOutput.textContent && rsaOutput.textContent !== '-') {
            navigator.clipboard.writeText(rsaOutput.textContent);
            showToast('RSA result copied to clipboard!', 'success');
        }
    });

    // --- TAB 3: Image Steganography ---
    const stegoCoverInput = document.getElementById('stego-cover-input');
    const stegoExtractInput = document.getElementById('stego-extract-input');
    const stegoCanvas = document.getElementById('stego-canvas');
    const stegoSecret = document.getElementById('stego-secret-input');
    const stegoPass = document.getElementById('stego-passphrase');
    const stegoOutput = document.getElementById('stego-output');
    const stegoCapTag = document.getElementById('stego-capacity-tag');

    const stegoEmbedDrop = document.getElementById('stego-embed-drop');
    stegoEmbedDrop.addEventListener('click', () => stegoCoverInput.click());

    stegoCoverInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) loadStegoImage(e.target.files[0]);
    });

    function loadStegoImage(file) {
        const reader = new FileReader();
        reader.onload = (evt) => {
            const img = new Image();
            img.onload = () => {
                stegoCanvas.width = img.width;
                stegoCanvas.height = img.height;
                const ctx = stegoCanvas.getContext('2d');
                ctx.drawImage(img, 0, 0);

                const maxCap = Math.floor((img.width * img.height * 2) / 8);
                stegoCapTag.textContent = `Capacity: ${maxCap.toLocaleString()} Bytes`;
                showToast(`Image loaded (${img.width}x${img.height}px). Max capacity: ${maxCap} bytes`, 'info');
            };
            img.src = evt.target.result;
        };
        reader.readAsDataURL(file);
    }

    document.getElementById('btn-stego-embed').addEventListener('click', async () => {
        const secret = stegoSecret.value;
        const pass = stegoPass.value;
        if (!secret) return showToast('Please enter secret message to embed!', 'warning');
        if (!stegoCanvas.width) return showToast('Please upload a cover image first!', 'warning');

        try {
            const cap = await CryptoEngine.embedStego(stegoCanvas, secret, pass);
            showToast('Payload hidden in image pixels successfully!', 'success');
        } catch (err) {
            showToast(err.message, 'warning');
        }
    });

    const stegoExtractDrop = document.getElementById('stego-extract-drop');
    stegoExtractDrop.addEventListener('click', () => stegoExtractInput.click());
    stegoExtractInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) loadStegoImage(e.target.files[0]);
    });

    document.getElementById('btn-stego-extract').addEventListener('click', async () => {
        if (!stegoCanvas.width) return showToast('Please load stego image first!', 'warning');
        const pass = stegoPass.value;

        try {
            const extractedPayload = await CryptoEngine.extractStego(stegoCanvas, pass);
            stegoOutput.textContent = extractedPayload;
            showToast('Steganography payload extracted!', 'success');
        } catch (err) {
            showToast(err.message, 'warning');
            stegoOutput.textContent = '-';
        }
    });

    document.getElementById('btn-stego-download').addEventListener('click', () => {
        if (!stegoCanvas.width) return showToast('No image in canvas to download!', 'warning');
        const link = document.createElement('a');
        link.download = 'stego_secret_image.png';
        link.href = stegoCanvas.toDataURL('image/png');
        link.click();
        showToast('Stego PNG downloaded!', 'success');
    });

    // --- TAB 4: Hashing & HMAC Suite ---
    const hashInput = document.getElementById('hash-input');
    const hashSha256 = document.getElementById('hash-sha256');
    const hashSha512 = document.getElementById('hash-sha512');
    const hashMd5 = document.getElementById('hash-md5');

    hashInput.addEventListener('input', async () => {
        const val = hashInput.value;
        if (!val) {
            hashSha256.textContent = '-';
            hashSha512.textContent = '-';
            hashMd5.textContent = '-';
            return;
        }

        hashSha256.textContent = await CryptoEngine.computeHash(val, 'SHA-256');
        hashSha512.textContent = await CryptoEngine.computeHash(val, 'SHA-512');
        hashMd5.textContent = await CryptoEngine.computeHash(val, 'MD5');
    });

    const hashFileDrop = document.getElementById('hash-file-drop');
    const hashFileInput = document.getElementById('hash-file-input');
    hashFileDrop.addEventListener('click', () => hashFileInput.click());
    hashFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) calculateFileHash(e.target.files[0]);
    });

    async function calculateFileHash(file) {
        showToast(`Calculating hashes for ${file.name}...`, 'info');
        const reader = new FileReader();
        reader.onload = async (evt) => {
            const buf = evt.target.result;
            hashSha256.textContent = await CryptoEngine.computeHash(buf, 'SHA-256');
            hashSha512.textContent = await CryptoEngine.computeHash(buf, 'SHA-512');
            hashMd5.textContent = await CryptoEngine.computeHash(buf, 'MD5');
            showToast('File hash integrity calculation complete!', 'success');
        };
        reader.readAsArrayBuffer(file);
    }

    // HMAC
    document.getElementById('btn-hmac-compute').addEventListener('click', async () => {
        const algo = document.getElementById('hmac-algo').value;
        const key = document.getElementById('hmac-key').value;
        const msg = document.getElementById('hmac-input').value;
        const hmacOutput = document.getElementById('hmac-output');

        if (!key) return showToast('Enter secret key for HMAC!', 'warning');
        if (!msg) return showToast('Enter message payload for HMAC!', 'warning');

        const signature = await CryptoEngine.computeHMAC(key, msg, algo);
        hmacOutput.textContent = signature;
        showToast('HMAC signature generated!', 'success');
    });

    // --- TAB 5: Classic Ciphers & Cryptanalysis ---
    const classicAlgoSelect = document.getElementById('classic-algo');
    const caesarRange = document.getElementById('caesar-shift');
    const lblCaesarShift = document.getElementById('lbl-caesar-shift');
    const groupCaesar = document.getElementById('group-caesar-shift');
    const groupClassicKey = document.getElementById('group-classic-key');
    const classicKey = document.getElementById('classic-key');
    const classicInput = document.getElementById('classic-input');
    const classicOutput = document.getElementById('classic-output');

    const chartContainer = document.getElementById('chart-frequency');
    const statIoC = document.getElementById('stat-ioc');
    const statCipherType = document.getElementById('stat-cipher-type');
    const crackOutput = document.getElementById('crack-output');

    classicAlgoSelect.addEventListener('change', () => {
        const val = classicAlgoSelect.value;
        if (val === 'caesar') {
            groupCaesar.style.display = 'flex';
            groupClassicKey.style.display = 'none';
        } else if (val === 'vigenere' || val === 'railfence' || val === 'playfair') {
            groupCaesar.style.display = 'none';
            groupClassicKey.style.display = 'flex';
        } else {
            groupCaesar.style.display = 'none';
            groupClassicKey.style.display = 'none';
        }
    });

    caesarRange.addEventListener('input', () => {
        lblCaesarShift.textContent = caesarRange.value;
    });

    document.getElementById('btn-classic-encrypt').addEventListener('click', () => {
        runClassicCipher(false);
    });

    document.getElementById('btn-classic-decrypt').addEventListener('click', () => {
        runClassicCipher(true);
    });

    function runClassicCipher(decrypt) {
        const algo = classicAlgoSelect.value;
        const text = classicInput.value;
        let res = '';

        if (!text) return showToast('Enter input text for cipher!', 'warning');

        if (algo === 'caesar') {
            res = CryptoEngine.caesarCipher(text, caesarRange.value, decrypt);
        } else if (algo === 'vigenere') {
            res = CryptoEngine.vigenereCipher(text, classicKey.value, decrypt);
        } else if (algo === 'railfence') {
            res = CryptoEngine.railFenceCipher(text, classicKey.value, decrypt);
        } else if (algo === 'rot13') {
            res = CryptoEngine.rot13(text);
        }

        classicOutput.textContent = res;
        updateFrequencyAnalysis(res);
    }

    classicInput.addEventListener('input', () => {
        updateFrequencyAnalysis(classicInput.value);
    });

    function updateFrequencyAnalysis(str) {
        const analysis = CryptoAnalyzer.analyzeFrequency(str);
        statIoC.textContent = analysis.ioc;

        const iocVal = parseFloat(analysis.ioc);
        if (iocVal > 0.060) statCipherType.textContent = 'Monoalphabetic / English Plaintext';
        else if (iocVal > 0.040) statCipherType.textContent = 'Polyalphabetic (Vigenère)';
        else statCipherType.textContent = 'Random / Transposition';

        CryptoAnalyzer.renderHistogram(chartContainer, analysis.frequencies);
    }

    document.getElementById('btn-classic-autocrack').addEventListener('click', () => {
        const text = classicInput.value || classicOutput.textContent;
        if (!text) return showToast('Enter ciphertext to auto-crack!', 'warning');

        const crack = CryptoAnalyzer.autoCrackCaesar(text);
        crackOutput.innerHTML = `<strong>Best Shift Candidate:</strong> ${crack.shift}<br>
                             <strong>Chi-Square Fit:</strong> ${crack.chiSquareScore}<br>
                             <strong>Decrypted Text:</strong> <span style="color:var(--cyan)">${crack.plaintext}</span>`;
        showToast(`Caesar shift ${crack.shift} identified!`, 'success');
    });

    // --- TAB 6: Password & Entropy Studio ---
    const entropyInput = document.getElementById('entropy-input');
    const barEntropy = document.getElementById('bar-entropy');
    const lblEntropyBits = document.getElementById('lbl-entropy-bits');
    const lblStrengthGrade = document.getElementById('lbl-strength-grade');
    const lblCrackTime = document.getElementById('lbl-crack-time');

    const chipLower = document.getElementById('chip-lowercase');
    const chipUpper = document.getElementById('chip-uppercase');
    const chipDigits = document.getElementById('chip-digits');
    const chipSymbols = document.getElementById('chip-symbols');

    function updateEntropyStats() {
        const pass = entropyInput.value;
        const res = CryptoAnalyzer.evaluatePassword(pass);
        const shannon = CryptoAnalyzer.calculateShannonEntropy(pass);

        lblEntropyBits.textContent = `${shannon.entropy} bits/char (${shannon.totalBits} total bits)`;
        lblStrengthGrade.textContent = res.grade;
        lblStrengthGrade.className = `lbl-strength ${res.gradeClass}`;
        lblCrackTime.textContent = res.crackTimeStr;

        const barPct = Math.min((parseFloat(shannon.totalBits) / 128) * 100, 100);
        barEntropy.style.width = `${barPct}%`;
        barEntropy.className = `progress-bar-fill bg-${res.gradeClass}`;

        chipLower.textContent = `abc (${res.classes.lower})`;
        chipUpper.textContent = `ABC (${res.classes.upper})`;
        chipDigits.textContent = `123 (${res.classes.digits})`;
        chipSymbols.textContent = `!@# (${res.classes.symbols})`;
    }

    entropyInput.addEventListener('input', updateEntropyStats);
    updateEntropyStats();

    // Secure Key Generator
    const genLen = document.getElementById('gen-len');
    const lblGenLen = document.getElementById('lbl-gen-len');
    const genOutput = document.getElementById('gen-output');

    genLen.addEventListener('input', () => lblGenLen.textContent = genLen.value);

    document.getElementById('btn-gen-pass').addEventListener('click', () => {
        const len = parseInt(genLen.value, 10);
        const useUpper = document.getElementById('chk-upper').checked;
        const useLower = document.getElementById('chk-lower').checked;
        const useDigits = document.getElementById('chk-digits').checked;
        const useSymbols = document.getElementById('chk-symbols').checked;

        let chars = '';
        if (useUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (useLower) chars += 'abcdefghijklmnopqrstuvwxyz';
        if (useDigits) chars += '0123456789';
        if (useSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (!chars) return showToast('Select at least one character set!', 'warning');

        const randomValues = new Uint32Array(len);
        window.crypto.getRandomValues(randomValues);

        let pass = '';
        for (let i = 0; i < len; i++) {
            pass += chars[randomValues[i] % chars.length];
        }

        genOutput.textContent = pass;
        entropyInput.value = pass;
        updateEntropyStats();
        showToast('Secure PRNG Key generated!', 'success');
    });

    document.getElementById('btn-gen-copy').addEventListener('click', () => {
        if (genOutput.textContent && genOutput.textContent !== 'Click button to generate...') {
            navigator.clipboard.writeText(genOutput.textContent);
            showToast('Key copied to clipboard!', 'success');
        }
    });

    // --- TAB 7: Codecs & JWT ---
    const codecFormat = document.getElementById('codec-format');
    const codecInput = document.getElementById('codec-input');
    const codecOutput = document.getElementById('codec-output');

    document.getElementById('btn-codec-encode').addEventListener('click', () => {
        const fmt = codecFormat.value;
        const val = codecInput.value;
        if (!val) return showToast('Enter data to encode!', 'warning');

        if (fmt === 'base64') codecOutput.textContent = window.btoa(val);
        else if (fmt === 'hex') codecOutput.textContent = CryptoEngine.bytesToHex(CryptoEngine.stringToUint8Array(val));
        else if (fmt === 'binary') codecOutput.textContent = Array.from(CryptoEngine.stringToUint8Array(val)).map(b => b.toString(2).padStart(8, '0')).join(' ');
        else if (fmt === 'url') codecOutput.textContent = encodeURIComponent(val);

        showToast(`Encoded to ${fmt.toUpperCase()}!`, 'success');
    });

    document.getElementById('btn-codec-decode').addEventListener('click', () => {
        const fmt = codecFormat.value;
        const val = codecInput.value.trim();
        if (!val) return showToast('Enter data to decode!', 'warning');

        try {
            if (fmt === 'base64') codecOutput.textContent = window.atob(val);
            else if (fmt === 'hex') codecOutput.textContent = CryptoEngine.uint8ArrayToString(CryptoEngine.hexToBytes(val));
            else if (fmt === 'binary') {
                const bytes = val.split(' ').map(bin => parseInt(bin, 2));
                codecOutput.textContent = CryptoEngine.uint8ArrayToString(new Uint8Array(bytes));
            }
            else if (fmt === 'url') codecOutput.textContent = decodeURIComponent(val);
            showToast(`Decoded from ${fmt.toUpperCase()}!`, 'success');
        } catch (e) {
            showToast('Decoding failed! Invalid input format.', 'warning');
        }
    });

    // JWT Decoder
    document.getElementById('btn-jwt-decode').addEventListener('click', () => {
        const jwtStr = document.getElementById('jwt-input').value;
        const jwtOutput = document.getElementById('jwt-output');
        if (!jwtStr) return showToast('Paste a JWT token string!', 'warning');

        try {
            const decoded = CryptoEngine.decodeJWT(jwtStr);
            jwtOutput.innerHTML = `<strong>HEADER:</strong><br><pre>${JSON.stringify(decoded.header, null, 2)}</pre><br>
                             <strong>PAYLOAD:</strong><br><pre>${JSON.stringify(decoded.payload, null, 2)}</pre>`;
            showToast('JWT Header & Payload decoded!', 'success');
        } catch (err) {
            showToast(err.message, 'warning');
        }
    });

    // --- QR Code Modal ---
    const qrModal = document.getElementById('qr-modal');
    const qrContainer = document.getElementById('qr-container');
    const btnCloseQr = document.getElementById('btn-close-qr');

    document.getElementById('btn-aes-qr').addEventListener('click', () => {
        const text = aesOutput.textContent;
        if (!text || text === '-') return showToast('No ciphertext available for QR code!', 'warning');

        qrContainer.innerHTML = '';
        // SVG QR Code Fallback Generator
        const svg = createSimpleQRSVG(text.substring(0, 100));
        qrContainer.appendChild(svg);
        qrModal.classList.add('active');
    });

    btnCloseQr.addEventListener('click', () => qrModal.classList.remove('active'));
    qrModal.addEventListener('click', (e) => {
        if (e.target === qrModal) qrModal.classList.remove('active');
    });

    function createSimpleQRSVG(text) {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('width', '200');
        svg.setAttribute('height', '200');
        svg.setAttribute('viewBox', '0 0 25 25');
        svg.style.background = '#fff';
        svg.style.padding = '10px';
        svg.style.borderRadius = '8px';

        // Pseudorandom grid representation for visual QR simulation
        for (let r = 0; r < 25; r++) {
            for (let c = 0; c < 25; c++) {
                // Corner alignment boxes
                const isCorner = (r < 7 && c < 7) || (r < 7 && c > 17) || (r > 17 && c < 7);
                const charCode = text.charCodeAt((r * 25 + c) % text.length);
                if (isCorner || (charCode * (r + 1) * (c + 1)) % 2 === 0) {
                    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                    rect.setAttribute('x', c);
                    rect.setAttribute('y', r);
                    rect.setAttribute('width', '1');
                    rect.setAttribute('height', '1');
                    rect.setAttribute('fill', '#000');
                    svg.appendChild(rect);
                }
            }
        }
        return svg;
    }

    // Initial entropy test render
    updateEntropyStats();
});
