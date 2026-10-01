/**
 * CipherVault Studio - Cryptography & Steganography Engine
 * Pure Client-Side Implementation using Web Crypto API & Modern Web APIs
 */

const CryptoEngine = (function () {
  'use strict';

  // --- Utility Helpers ---

  function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64.replace(/\s/g, ''));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function stringToUint8Array(str) {
    return new TextEncoder().encode(str);
  }

  function uint8ArrayToString(arr) {
    return new TextDecoder().decode(arr);
  }

  function bytesToHex(uint8Array) {
    return Array.from(uint8Array)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function hexToBytes(hexString) {
    hexString = hexString.replace(/\s/g, '');
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
      bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
    }
    return bytes;
  }

  // --- Symmetric Encryption (AES-GCM / AES-CBC) ---

  async function deriveKeyPBKDF2(passphrase, salt, mode = 'AES-GCM', iterations = 100000) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: mode, length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptAES(passphrase, plaintext, mode = 'AES-GCM') {
    if (!passphrase) throw new Error('Passphrase is required for AES encryption.');
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(mode === 'AES-GCM' ? 12 : 16));
    const derivedKey = await deriveKeyPBKDF2(passphrase, salt, mode);

    const encodedData = stringToUint8Array(plaintext);
    let encryptedBuffer;

    if (mode === 'AES-GCM') {
      encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        derivedKey,
        encodedData
      );
    } else {
      encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: iv },
        derivedKey,
        encodedData
      );
    }

    return {
      ciphertextBase64: arrayBufferToBase64(encryptedBuffer),
      saltHex: bytesToHex(salt),
      ivHex: bytesToHex(iv),
      mode: mode
    };
  }

  async function decryptAES(passphrase, ciphertextBase64, saltHex, ivHex, mode = 'AES-GCM') {
    if (!passphrase) throw new Error('Passphrase is required for AES decryption.');
    const salt = hexToBytes(saltHex);
    const iv = hexToBytes(ivHex);
    const ciphertextBuffer = base64ToArrayBuffer(ciphertextBase64);
    const derivedKey = await deriveKeyPBKDF2(passphrase, salt, mode);

    let decryptedBuffer;
    try {
      if (mode === 'AES-GCM') {
        decryptedBuffer = await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv },
          derivedKey,
          ciphertextBuffer
        );
      } else {
        decryptedBuffer = await window.crypto.subtle.decrypt(
          { name: 'AES-CBC', iv: iv },
          derivedKey,
          ciphertextBuffer
        );
      }
    } catch (err) {
      throw new Error('Decryption failed! Invalid passphrase, corrupted IV/Salt, or altered ciphertext.');
    }

    return uint8ArrayToString(new Uint8Array(decryptedBuffer));
  }

  // File Container (.enc) Encryption / Decryption
  async function packEncryptedFile(fileBuffer, passphrase) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKeyPBKDF2(passphrase, salt, 'AES-GCM');

    const encryptedContent = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      fileBuffer
    );

    // Magic Header CVULT01 (7 bytes) + Salt (16) + IV (12) + Payload
    const magic = stringToUint8Array('CVULT01');
    const fullBuffer = new Uint8Array(magic.length + salt.length + iv.length + encryptedContent.byteLength);

    fullBuffer.set(magic, 0);
    fullBuffer.set(salt, magic.length);
    fullBuffer.set(iv, magic.length + salt.length);
    fullBuffer.set(new Uint8Array(encryptedContent), magic.length + salt.length + iv.length);

    return fullBuffer;
  }

  async function unpackEncryptedFile(encBuffer, passphrase) {
    const magic = uint8ArrayToString(encBuffer.slice(0, 7));
    if (magic !== 'CVULT01') {
      throw new Error('Invalid file format! Expected CipherVault .enc container.');
    }

    const salt = encBuffer.slice(7, 23);
    const iv = encBuffer.slice(23, 35);
    const ciphertext = encBuffer.slice(35);

    const key = await deriveKeyPBKDF2(passphrase, salt, 'AES-GCM');
    try {
      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        ciphertext
      );
      return decrypted;
    } catch (err) {
      throw new Error('File decryption failed! Incorrect passphrase or corrupted file.');
    }
  }

  // --- Asymmetric RSA (RSA-OAEP 2048/4096 bit) ---

  async function generateRSAKeyPair(modulusLength = 2048) {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: parseInt(modulusLength, 10),
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );

    const pubExported = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privExported = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    const pubPEM = `-----BEGIN PUBLIC KEY-----\n${formatPEM(arrayBufferToBase64(pubExported))}\n-----END PUBLIC KEY-----`;
    const privPEM = `-----BEGIN PRIVATE KEY-----\n${formatPEM(arrayBufferToBase64(privExported))}\n-----END PRIVATE KEY-----`;

    return { publicKeyPEM: pubPEM, privateKeyPEM: privPEM };
  }

  function formatPEM(b64String) {
    return b64String.match(/.{1,64}/g).join('\n');
  }

  function pemToBuffer(pemString) {
    const lines = pemString.trim().split('\n');
    const b64 = lines.filter(l => !l.startsWith('---')).join('');
    return base64ToArrayBuffer(b64);
  }

  async function encryptRSA(publicKeyPEM, plaintext) {
    const keyBuffer = pemToBuffer(publicKeyPEM);
    const pubKey = await window.crypto.subtle.importKey(
      'spki',
      keyBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );

    const encoded = stringToUint8Array(plaintext);
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      pubKey,
      encoded
    );

    return arrayBufferToBase64(encrypted);
  }

  async function decryptRSA(privateKeyPEM, ciphertextBase64) {
    const keyBuffer = pemToBuffer(privateKeyPEM);
    const privKey = await window.crypto.subtle.importKey(
      'pkcs8',
      keyBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt']
    );

    const encryptedBuffer = base64ToArrayBuffer(ciphertextBase64);
    try {
      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privKey,
        encryptedBuffer
      );
      return uint8ArrayToString(new Uint8Array(decrypted));
    } catch (e) {
      throw new Error('RSA decryption failed! Check if private key matches the public key used for encryption.');
    }
  }

  // --- LSB Image Steganography ---

  async function embedStego(canvas, textPayload, passphrase = '') {
    let finalPayload = textPayload;
    if (passphrase.trim()) {
      const enc = await encryptAES(passphrase, textPayload, 'AES-GCM');
      finalPayload = `ENC:${enc.saltHex}:${enc.ivHex}:${enc.ciphertextBase64}`;
    }

    const payloadBytes = stringToUint8Array(finalPayload);
    const ctx = canvas.getContext('2d');
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imgData.data;

    // Header: 4 bytes Magic 'STG1' + 4 bytes Length (uint32)
    const totalBytesNeeded = 8 + payloadBytes.length;
    const maxCapacityBytes = Math.floor((data.length / 4) * 2 / 8); // 2 bits per pixel (R, G)

    if (totalBytesNeeded > maxCapacityBytes) {
      throw new Error(`Payload too large for image! Requires ${totalBytesNeeded} bytes, max capacity is ${maxCapacityBytes} bytes.`);
    }

    const fullBuffer = new Uint8Array(totalBytesNeeded);
    fullBuffer.set(stringToUint8Array('STG1'), 0);
    const lenView = new DataView(fullBuffer.buffer);
    lenView.setUint32(4, payloadBytes.length, false); // Big endian
    fullBuffer.set(payloadBytes, 8);

    // Embed bits into LSB of R and G channels
    let bitIdx = 0;
    const totalBits = totalBytesNeeded * 8;

    for (let i = 0; i < data.length && bitIdx < totalBits; i += 4) {
      for (let channel = 0; channel < 2 && bitIdx < totalBits; channel++) {
        const byteIdx = Math.floor(bitIdx / 8);
        const bitOffset = 7 - (bitIdx % 8);
        const bit = (fullBuffer[byteIdx] >> bitOffset) & 1;

        data[i + channel] = (data[i + channel] & 0xFE) | bit;
        bitIdx++;
      }
    }

    ctx.putImageData(imgData, 0, 0);
    return maxCapacityBytes;
  }

  async function extractStego(canvas, passphrase = '') {
    const ctx = canvas.getContext('2d');
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imgData.data;

    // Read first 8 bytes (64 bits) for header
    const headerBytes = new Uint8Array(8);
    let bitIdx = 0;

    for (let i = 0; i < data.length && bitIdx < 64; i += 4) {
      for (let channel = 0; channel < 2 && bitIdx < 64; channel++) {
        const bit = data[i + channel] & 1;
        const byteIdx = Math.floor(bitIdx / 8);
        const bitOffset = 7 - (bitIdx % 8);
        headerBytes[byteIdx] |= (bit << bitOffset);
        bitIdx++;
      }
    }

    const magic = uint8ArrayToString(headerBytes.slice(0, 4));
    if (magic !== 'STG1') {
      throw new Error('No valid steganography signature found in image!');
    }

    const lenView = new DataView(headerBytes.buffer);
    const payloadLength = lenView.getUint32(4, false);

    if (payloadLength <= 0 || payloadLength > (data.length / 4)) {
      throw new Error('Corrupted or invalid steganography payload size.');
    }

    const payloadBytes = new Uint8Array(payloadLength);
    const totalBitsNeeded = (8 + payloadLength) * 8;
    bitIdx = 0;

    for (let i = 0; i < data.length && bitIdx < totalBitsNeeded; i += 4) {
      for (let channel = 0; channel < 2 && bitIdx < totalBitsNeeded; channel++) {
        if (bitIdx >= 64) {
          const payloadBitIdx = bitIdx - 64;
          const bit = data[i + channel] & 1;
          const byteIdx = Math.floor(payloadBitIdx / 8);
          const bitOffset = 7 - (payloadBitIdx % 8);
          payloadBytes[byteIdx] |= (bit << bitOffset);
        }
        bitIdx++;
      }
    }

    const rawPayload = uint8ArrayToString(payloadBytes);
    if (rawPayload.startsWith('ENC:')) {
      if (!passphrase) {
        throw new Error('Payload is encrypted! Please enter passphrase to decrypt.');
      }
      const parts = rawPayload.split(':');
      const saltHex = parts[1];
      const ivHex = parts[2];
      const cipherB64 = parts[3];
      return await decryptAES(passphrase, cipherB64, saltHex, ivHex, 'AES-GCM');
    }

    return rawPayload;
  }

  // --- Hashing & HMAC Suite ---

  async function computeHash(data, algo = 'SHA-256') {
    let buffer;
    if (typeof data === 'string') {
      buffer = stringToUint8Array(data);
    } else if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
      buffer = data;
    }

    if (algo === 'MD5') {
      return computeMD5(buffer);
    }

    const hashBuffer = await window.crypto.subtle.digest(algo, buffer);
    return bytesToHex(new Uint8Array(hashBuffer));
  }

  async function computeHMAC(keyStr, messageStr, algo = 'SHA-256') {
    const enc = new TextEncoder();
    const key = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(keyStr),
      { name: 'HMAC', hash: algo },
      false,
      ['sign']
    );

    const signature = await window.crypto.subtle.encrypt
      ? await window.crypto.subtle.sign('HMAC', key, enc.encode(messageStr))
      : null;

    return bytesToHex(new Uint8Array(signature));
  }

  // MD5 JS Implementation for Browser Completeness
  function computeMD5(input) {
    let bytes;
    if (typeof input === 'string') bytes = stringToUint8Array(input);
    else bytes = new Uint8Array(input);

    function md5cycle(x, k) {
      let a = x[0], b = x[1], c = x[2], d = x[3];
      a = ff(a, b, c, d, k[0], 7, -680876936); d = ff(d, a, b, c, k[1], 12, -389564586);
      c = ff(c, d, a, b, k[2], 17, 606105819); b = ff(b, c, d, a, k[3], 22, -1044525330);
      a = ff(a, b, c, d, k[4], 7, -176418897); d = ff(d, a, b, c, k[5], 12, 1200080426);
      c = ff(c, d, a, b, k[6], 17, -1473231341); b = ff(b, c, d, a, k[7], 22, -45705983);
      a = ff(a, b, c, d, k[8], 7, 1770035416); d = ff(d, a, b, c, k[9], 12, -1958414417);
      c = ff(c, d, a, b, k[10], 17, -42063); b = ff(b, c, d, a, k[11], 22, -1990404162);
      a = ff(a, b, c, d, k[12], 7, 1804603682); d = ff(d, a, b, c, k[13], 12, -40341101);
      c = ff(c, d, a, b, k[14], 17, -1502002290); b = ff(b, c, d, a, k[15], 22, 1236535329);

      a = gg(a, b, c, d, k[1], 5, -165796510); d = gg(d, a, b, c, k[6], 9, -1069501632);
      c = gg(c, d, a, b, k[11], 14, 643717713); b = gg(b, c, d, a, k[0], 20, -373897302);
      a = gg(a, b, c, d, k[5], 5, -701558691); d = gg(d, a, b, c, k[10], 9, 38016083);
      c = gg(c, d, a, b, k[15], 14, -660478335); b = gg(b, c, d, a, k[4], 20, -405537848);
      a = gg(a, b, c, d, k[9], 5, 568446438); d = gg(d, a, b, c, k[14], 9, -1019803690);
      c = gg(c, d, a, b, k[3], 14, -187363961); b = gg(b, c, d, a, k[8], 20, 1163531501);
      a = gg(a, b, c, d, k[13], 5, -144468057); d = gg(d, a, b, c, k[2], 9, -51403784);
      c = gg(c, d, a, b, k[7], 14, 1735328473); b = gg(b, c, d, a, k[12], 20, -1926607734);

      a = hh(a, b, c, d, k[5], 4, -378558); d = hh(d, a, b, c, k[8], 11, -2022574463);
      c = hh(c, d, a, b, k[11], 16, 1839030562); b = hh(b, c, d, a, k[14], 23, -35309556);
      a = hh(a, b, c, d, k[1], 4, -1530992060); d = hh(d, a, b, c, k[4], 11, 1272893353);
      c = hh(c, d, a, b, k[7], 16, -155497632); b = hh(b, c, d, a, k[10], 23, -1094730640);
      a = hh(a, b, c, d, k[13], 4, 681279174); d = hh(d, a, b, c, k[0], 11, -358537222);
      c = hh(c, d, a, b, k[3], 16, -722521979); b = hh(b, c, d, a, k[6], 23, 76029189);

      a = ii(a, b, c, d, k[0], 6, -198630844); d = ii(d, a, b, c, k[7], 10, 1126891415);
      c = ii(c, d, a, b, k[14], 15, -1416354905); b = ii(b, c, d, a, k[5], 21, -57434055);
      a = ii(a, b, c, d, k[12], 6, 1700485571); d = ii(d, a, b, c, k[3], 10, -1894980791);
      c = ii(c, d, a, b, k[10], 15, -1051523); b = ii(b, c, d, a, k[1], 21, -2054922799);
      a = ii(a, b, c, d, k[8], 6, 1873313359); d = ii(d, a, b, c, k[15], 10, -30611744);
      c = ii(c, d, a, b, k[6], 15, -1560198380); b = ii(b, c, d, a, k[13], 21, 1309151649);
      a = ii(a, b, c, d, k[4], 6, -145523070); d = ii(d, a, b, c, k[11], 10, -1120210379);
      c = ii(c, d, a, b, k[2], 15, 718787259); b = ii(b, c, d, a, k[9], 21, -343485551);

      x[0] = add32(a, x[0]); x[1] = add32(b, x[1]); x[2] = add32(c, x[2]); x[3] = add32(d, x[3]);
    }

    function cmn(q, a, b, x, s, t) {
      a = add32(add32(a, q), add32(x, t));
      return add32((a << s) | (a >>> (32 - s)), b);
    }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }
    function add32(x, y) { return (x + y) & 0xFFFFFFFF; }

    const n = bytes.length;
    const state = [1732584193, -271733879, -1732584194, 271733878];
    let i;
    for (i = 64; i <= n; i += 64) {
      const block = [];
      for (let j = 0; j < 16; j++) {
        block[j] = bytes[i - 64 + j * 4] | (bytes[i - 64 + j * 4 + 1] << 8) | (bytes[i - 64 + j * 4 + 2] << 16) | (bytes[i - 64 + j * 4 + 3] << 24);
      }
      md5cycle(state, block);
    }
    const tail = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    for (let j = 0; j < n % 64; j++) {
      tail[j >> 2] |= bytes[i - 64 + j] << ((j % 4) << 3);
    }
    tail[(n % 64) >> 2] |= 0x80 << (((n % 64) % 4) << 3);
    if ((n % 64) > 55) {
      md5cycle(state, tail);
      for (let j = 0; j < 16; j++) tail[j] = 0;
    }
    tail[14] = n * 8;
    md5cycle(state, tail);

    return state.map(val => {
      let h = (val >>> 0).toString(16);
      while (h.length < 8) h = '0' + h;
      return h.match(/../g).reverse().join('');
    }).join('');
  }

  // --- Classic Cipher Engines ---

  function caesarCipher(str, shift, decrypt = false) {
    shift = parseInt(shift, 10) % 26;
    if (decrypt) shift = (26 - shift) % 26;

    return str.replace(/[a-zA-Z]/g, char => {
      const code = char.charCodeAt(0);
      const base = code >= 97 ? 97 : 65;
      return String.fromCharCode(((code - base + shift) % 26) + base);
    });
  }

  function vigenereCipher(str, key, decrypt = false) {
    if (!key) return str;
    key = key.toLowerCase().replace(/[^a-z]/g, '');
    if (!key) return str;

    let ki = 0;
    return str.replace(/[a-zA-Z]/g, char => {
      const code = char.charCodeAt(0);
      const base = code >= 97 ? 97 : 65;
      const kShift = key.charCodeAt(ki % key.length) - 97;
      ki++;

      const shift = decrypt ? (26 - kShift) % 26 : kShift;
      return String.fromCharCode(((code - base + shift) % 26) + base);
    });
  }

  function railFenceCipher(str, rails, decrypt = false) {
    rails = parseInt(rails, 10);
    if (!rails || rails <= 1) return str;

    const fence = Array.from({ length: rails }, () => []);
    let rail = 0, dir = 1;

    if (!decrypt) {
      for (let char of str) {
        fence[rail].push(char);
        rail += dir;
        if (rail === 0 || rail === rails - 1) dir = -dir;
      }
      return fence.flat().join('');
    } else {
      // Decrypt Rail Fence
      const pattern = Array.from({ length: str.length });
      rail = 0; dir = 1;
      for (let i = 0; i < str.length; i++) {
        pattern[i] = rail;
        rail += dir;
        if (rail === 0 || rail === rails - 1) dir = -dir;
      }

      const counts = Array(rails).fill(0);
      for (let r of pattern) counts[r]++;

      const resultFence = Array.from({ length: rails }, () => []);
      let pos = 0;
      for (let r = 0; r < rails; r++) {
        resultFence[r] = str.slice(pos, pos + counts[r]).split('');
        pos += counts[r];
      }

      rail = 0; dir = 1;
      let decrypted = '';
      for (let i = 0; i < str.length; i++) {
        decrypted += resultFence[rail].shift();
        rail += dir;
        if (rail === 0 || rail === rails - 1) dir = -dir;
      }
      return decrypted;
    }
  }

  function rot13(str) {
    return caesarCipher(str, 13);
  }

  // --- Codecs & JWT Decoder ---

  function decodeJWT(jwtString) {
    const parts = jwtString.trim().split('.');
    if (parts.length < 2) {
      throw new Error('Invalid JWT format! Token must contain header, payload, and signature separated by dots.');
    }

    try {
      const headerObj = JSON.parse(window.atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      const payloadObj = JSON.parse(window.atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      return { header: headerObj, payload: payloadObj };
    } catch (e) {
      throw new Error('Failed to parse JWT JSON payloads!');
    }
  }

  // API Export
  return {
    arrayBufferToBase64,
    base64ToArrayBuffer,
    stringToUint8Array,
    uint8ArrayToString,
    bytesToHex,
    hexToBytes,
    encryptAES,
    decryptAES,
    packEncryptedFile,
    unpackEncryptedFile,
    generateRSAKeyPair,
    encryptRSA,
    decryptRSA,
    embedStego,
    extractStego,
    computeHash,
    computeHMAC,
    caesarCipher,
    vigenereCipher,
    railFenceCipher,
    rot13,
    decodeJWT
  };
})();
