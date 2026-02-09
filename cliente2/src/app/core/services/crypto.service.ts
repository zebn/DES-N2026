import { Injectable } from '@angular/core';
import { argon2id } from 'hash-wasm';

@Injectable({
  providedIn: 'root'
})
export class CryptoService {

  // Cache de la clave privada descifrada (solo en memoria)
  private privateKeyCache: CryptoKey | null = null;
  private publicKeyCache: CryptoKey | null = null;

  // Claves para firma (RSA-PSS)
  private signingPrivateKeyCache: CryptoKey | null = null;
  private signingPublicKeyCache: CryptoKey | null = null;

  // ===== RSA Key Generation =====

  async generateRSAKeyPair(): Promise<CryptoKeyPair> {
    return await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true, // extractable
      ['encrypt', 'decrypt']
    );
  }

  // ===== Key Export/Import =====

  async exportPublicKey(key: CryptoKey): Promise<string> {
    const exported = await window.crypto.subtle.exportKey('spki', key);
    const base64 = this.arrayBufferToBase64(exported);

    // Format as PEM with proper line breaks (64 chars per line)
    const pemBody = base64.match(/.{1,64}/g)?.join('\n') || base64;
    return `-----BEGIN PUBLIC KEY-----\n${pemBody}\n-----END PUBLIC KEY-----`;
  }

  async exportPrivateKey(key: CryptoKey): Promise<string> {
    const exported = await window.crypto.subtle.exportKey('pkcs8', key);
    const base64 = this.arrayBufferToBase64(exported);

    // Format as PEM with proper line breaks (64 chars per line)
    const pemBody = base64.match(/.{1,64}/g)?.join('\n') || base64;
    return `-----BEGIN PRIVATE KEY-----\n${pemBody}\n-----END PRIVATE KEY-----`;
  }

  async importPublicKey(base64String: string): Promise<CryptoKey> {
    const keyData = this.base64ToArrayBuffer(base64String);
    return await window.crypto.subtle.importKey(
      'spki',
      keyData,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt']
    );
  }

  async importPrivateKey(base64String: string): Promise<CryptoKey> {
    const keyData = this.base64ToArrayBuffer(base64String);
    return await window.crypto.subtle.importKey(
      'pkcs8',
      keyData,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['decrypt']
    );
  }

  // Importar claves para firma digital (RSA-PSS)
  async importPublicKeyForSigning(base64String: string): Promise<CryptoKey> {
    const keyData = this.base64ToArrayBuffer(base64String);
    return await window.crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256'
      },
      true,
      ['verify']
    );
  }

  async importPrivateKeyForSigning(base64String: string): Promise<CryptoKey> {
    const keyData = this.base64ToArrayBuffer(base64String);
    return await window.crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256'
      },
      true,
      ['sign']
    );
  }

  // ===== RSA Encryption/Decryption =====

  async rsaEncrypt(data: ArrayBuffer, publicKey: CryptoKey): Promise<ArrayBuffer> {
    return await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      data
    );
  }

  async rsaDecrypt(encryptedData: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> {
    console.log('[CryptoService] rsaDecrypt input:', {
      encryptedDataLength: encryptedData.byteLength,
      encryptedDataPreview: Array.from(new Uint8Array(encryptedData).slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' '),
      privateKeyAlgorithm: privateKey.algorithm,
      privateKeyType: privateKey.type
    });

    try {
      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        encryptedData
      );

      console.log('[CryptoService] rsaDecrypt output length:', decrypted.byteLength);
      return decrypted;
    } catch (error) {
      console.error('[CryptoService] rsaDecrypt error:', error);
      console.error('[CryptoService] Error details:', {
        message: error instanceof Error ? error.message : 'Unknown error',
        name: error instanceof Error ? error.name : 'Unknown',
        encryptedLength: encryptedData.byteLength
      });
      throw error;
    }
  }

  // ===== AES Key Generation =====

  async generateAESKey(): Promise<CryptoKey> {
    return await window.crypto.subtle.generateKey(
      {
        name: 'AES-CTR',
        length: 256
      },
      true, // extractable
      ['encrypt', 'decrypt']
    );
  }

  // ===== AES Encryption/Decryption =====

  async aesEncrypt(data: ArrayBuffer, key: CryptoKey): Promise<{ ciphertext: ArrayBuffer, counter: Uint8Array }> {
    const counterBuffer = new ArrayBuffer(16);
    const counter = new Uint8Array(counterBuffer);
    window.crypto.getRandomValues(counter); // 128-bit counter for CTR

    // CTR mode does not require padding
    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: 'AES-CTR',
        counter: counterBuffer,
        length: 128  // Counter block size in bits
      },
      key,
      data
    );

    return { ciphertext, counter };
  }

  async aesDecrypt(ciphertext: ArrayBuffer, key: CryptoKey, counter: Uint8Array): Promise<ArrayBuffer> {
    console.log('[CryptoService] aesDecrypt input:', {
      ciphertextLength: ciphertext.byteLength,
      counterLength: counter.length,
      counterPreview: Array.from(counter.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join(' ')
    });

    try {
      // CTR mode does not use padding
      // Use counter.buffer to get ArrayBuffer (required by BufferSource type)
      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: 'AES-CTR',
          counter: counter.buffer.slice(counter.byteOffset, counter.byteOffset + counter.byteLength) as ArrayBuffer,
          length: 128  // Counter block size in bits
        },
        key,
        ciphertext
      );

      console.log('[CryptoService] Decrypted data length:', decrypted.byteLength);
      console.log('[CryptoService] Decrypted data preview:',
        Array.from(new Uint8Array(decrypted).slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ')
      );

      return decrypted;
    } catch (error) {
      console.error('[CryptoService] aesDecrypt error:', error);
      throw error;
    }
  }  // ===== Private Key Encryption (PBKDF2 + AES) =====

  async encryptPrivateKey(privateKeyString: string, password: string): Promise<{
    encryptedKey: string;
    salt: string;
    counter: string;
  }> {
    const salt = window.crypto.getRandomValues(new Uint8Array(32));

    // Derive key from password using PBKDF2
    const passwordKey = await this.deriveKeyFromPassword(password, salt);

    // Encrypt private key with derived key
    const privateKeyBytes = new TextEncoder().encode(privateKeyString);
    const { ciphertext, counter } = await this.aesEncrypt(privateKeyBytes.buffer, passwordKey);

    return {
      encryptedKey: this.arrayBufferToBase64(ciphertext),
      salt: this.uint8ArrayToBase64(salt),
      counter: this.uint8ArrayToBase64(counter)
    };
  }

  async decryptPrivateKey(
    encryptedKey: string,
    password: string,
    salt: string,
    counter?: string  // Optional - may be undefined for old encrypted keys
  ): Promise<string> {
    console.log('[CryptoService] decryptPrivateKey input:', {
      encryptedKeyLength: encryptedKey?.length,
      saltLength: salt?.length,
      counterLength: counter?.length,
      counterValue: counter,
      hasCounter: !!counter
    });

    const saltBytes = this.base64ToUint8Array(salt);

    // Derive key from password
    const passwordKey = await this.deriveKeyFromPassword(password, saltBytes);

    if (!counter) {
      throw new Error('Counter/IV requerido para descifrar clave privada. Base de datos debe migrarse.');
    }

    // AES-CTR format with counter
    const encryptedBytes = this.base64ToArrayBuffer(encryptedKey);
    let counterBytes = this.base64ToUint8Array(counter);

    console.log('[CryptoService] Decoded values:', {
      saltBytesLength: saltBytes.length,
      encryptedBytesLength: encryptedBytes.byteLength,
      counterBytesLength: counterBytes.length
    });

    // Validate counter is 16 bytes
    if (counterBytes.length !== 16) {
      throw new Error(`Counter debe ser 16 bytes, recibido: ${counterBytes.length}`);
    }

    // Decrypt
    const decrypted = await this.aesDecrypt(encryptedBytes, passwordKey, counterBytes);

    return new TextDecoder().decode(decrypted);
  }

  // Fernet support removed - migrated to AES-CTR

  private async deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey> {
    // Usar Argon2id para derivar clave AES
    const derivedKeyBytes = await argon2id({
      password: password,
      salt: salt,
      parallelism: 4,
      iterations: 3,
      memorySize: 65536,  // 64 MB en KB
      hashLength: 32,     // 256 bits para AES-256
      outputType: 'binary'
    });

    // Importar los bytes derivados como clave AES-CTR
    return await window.crypto.subtle.importKey(
      'raw',
      derivedKeyBytes.buffer as ArrayBuffer,
      { name: 'AES-CTR', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  // ===== File Encryption =====

  async encryptFile(file: File, recipientPublicKey: CryptoKey): Promise<{
    encryptedContent: string;
    encryptedAesKey: string;
    counter: string;
  }> {
    // 1. Generate AES key
    const aesKey = await this.generateAESKey();

    // 2. Read file
    const fileData = await this.readFileAsArrayBuffer(file);

    // 3. Encrypt file with AES
    const { ciphertext, counter } = await this.aesEncrypt(fileData, aesKey);

    // 4. Export AES key
    const aesKeyRaw = await window.crypto.subtle.exportKey('raw', aesKey);

    // 5. Encrypt AES key with RSA
    const encryptedAesKey = await this.rsaEncrypt(aesKeyRaw, recipientPublicKey);

    return {
      encryptedContent: this.arrayBufferToBase64(ciphertext),
      encryptedAesKey: this.arrayBufferToBase64(encryptedAesKey),
      counter: this.uint8ArrayToBase64(counter)
    };
  }

  async decryptFile(
    encryptedContent: string,
    encryptedAesKey: string,
    counter: string,
    privateKey: CryptoKey
  ): Promise<Blob> {
    // 1. Decrypt AES key with RSA
    const encryptedKeyBuffer = this.base64ToArrayBuffer(encryptedAesKey);
    const aesKeyBuffer = await this.rsaDecrypt(encryptedKeyBuffer, privateKey);

    // 2. Import AES key for AES-CTR
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      aesKeyBuffer,
      'AES-CTR',
      false,
      ['decrypt']
    );

    // 3. Decrypt file
    const ciphertext = this.base64ToArrayBuffer(encryptedContent);
    const counterBytes = this.base64ToUint8Array(counter);

    const decrypted = await this.aesDecrypt(ciphertext, aesKey, counterBytes);

    // 4. Return as Blob
    return new Blob([decrypted]);
  }

  /**
   * Decrypt file using cached private key
   * Uses AES-CTR mode - counter embedded as first 16 bytes of encrypted content
   */
  async decryptFileWithCachedKey(
    encryptedContent: string,
    encryptedAesKey: string,
    counter?: string
  ): Promise<ArrayBuffer> {
    if (!this.privateKeyCache) {
      throw new Error('Clave privada no disponible. Por favor, desbloquea tu clave primero.');
    }

    // 1. Decrypt AES key with RSA
    const encryptedKeyBuffer = this.base64ToArrayBuffer(encryptedAesKey);
    const aesKeyBuffer = await this.rsaDecrypt(encryptedKeyBuffer, this.privateKeyCache);

    // 2. Import AES key for AES-CTR
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      aesKeyBuffer,
      'AES-CTR',
      false,
      ['decrypt']
    );

    // 3. Decode encrypted content
    const encryptedWithCounter = this.base64ToArrayBuffer(encryptedContent);

    // 4. Extract counter and ciphertext
    // Backend stores counter as first 16 bytes of encrypted_content
    const counterBytes = new Uint8Array(encryptedWithCounter.slice(0, 16));
    const ciphertext = encryptedWithCounter.slice(16);

    console.log('[CryptoService] Decryption info:', {
      totalLength: encryptedWithCounter.byteLength,
      counterLength: counterBytes.length,
      ciphertextLength: ciphertext.byteLength,
      aesKeyLength: aesKeyBuffer.byteLength
    });

    // 5. Decrypt with AES-CTR (no padding removal needed)
    try {
      // Use buffer.slice() to get ArrayBuffer (required by BufferSource type)
      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: 'AES-CTR',
          counter: counterBytes.buffer.slice(counterBytes.byteOffset, counterBytes.byteOffset + counterBytes.byteLength) as ArrayBuffer,
          length: 128
        },
        aesKey,
        ciphertext
      );

      console.log('[CryptoService] Decryption successful:', {
        decryptedLength: decrypted.byteLength
      });

      return decrypted;
    } catch (error: any) {
      console.error('[CryptoService] Decryption failed:', {
        error: error.message,
        name: error.name,
        aesKeyLength: aesKeyBuffer.byteLength,
        counterLength: counterBytes.length,
        ciphertextLength: ciphertext.byteLength
      });
      throw error;
    }
  }

  // Encrypt file for upload (uses user's own public key)
  async encryptFileForUpload(fileData: Uint8Array): Promise<{
    encrypted_content: string;
    encrypted_aes_key: string;
    counter: string;
    file_hash: string;
    digital_signature: string;
  }> {
    // 1. Generate AES key for this file
    const aesKey = await this.generateAESKey();

    // 2. Encrypt file content with AES-CTR
    const { ciphertext, counter } = await this.aesEncrypt(fileData.buffer as ArrayBuffer, aesKey);

    // 3. Calculate SHA-256 hash of original file
    const fileHash = await this.sha256(fileData.buffer as ArrayBuffer);

    // 4. Get user's public key from cache
    const publicKey = await this.getPublicKey();

    // 5. Export and wrap AES key with user's public key
    const aesKeyRaw = await window.crypto.subtle.exportKey('raw', aesKey);
    const wrappedKey = await this.rsaEncrypt(aesKeyRaw, publicKey);

    // 6. Generate digital signature using RSA-PSS
    if (!this.signingPrivateKeyCache) {
      throw new Error('Clave de firma no disponible. Por favor, cierra sesión y vuelve a iniciar.');
    }

    // IMPORTANTE: Firmar los bytes UTF-8 del hash HEX (igual que Python: file_hash.encode())
    const hashBytes = new TextEncoder().encode(fileHash);

    console.log('[CryptoService] Signing data:', {
      hashLength: hashBytes.length,
      hashPreview: fileHash.substring(0, 32),
      keyAlgorithm: this.signingPrivateKeyCache.algorithm
    });

    const signature = await window.crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: 0
      },
      this.signingPrivateKeyCache,
      hashBytes
    );

    console.log('[CryptoService] Signature generated, length:', signature.byteLength);

    // Concatenate counter + ciphertext (like Python client does)
    const encryptedWithCounter = new Uint8Array(counter.length + ciphertext.byteLength);
    encryptedWithCounter.set(counter);
    encryptedWithCounter.set(new Uint8Array(ciphertext), counter.length);

    return {
      encrypted_content: this.arrayBufferToBase64(encryptedWithCounter.buffer),
      encrypted_aes_key: this.arrayBufferToBase64(wrappedKey),
      counter: this.uint8ArrayToBase64(counter),
      file_hash: fileHash,
      digital_signature: this.arrayBufferToBase64(signature)
    };
  }

  // ===== Digital Signatures =====

  async generateSigningKeyPair(): Promise<CryptoKeyPair> {
    return await window.crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['sign', 'verify']
    );
  }

  async signData(data: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> {
    return await window.crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: 32
      },
      privateKey,
      data
    );
  }

  async verifySignature(
    signature: ArrayBuffer,
    data: ArrayBuffer,
    publicKey: CryptoKey
  ): Promise<boolean> {
    return await window.crypto.subtle.verify(
      {
        name: 'RSA-PSS',
        saltLength: 32
      },
      publicKey,
      signature,
      data
    );
  }

  // ===== Hashing =====

  async sha256(data: ArrayBuffer): Promise<string> {
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    return this.arrayBufferToHex(hashBuffer);
  }

  // ===== PKCS7 Padding (removed - AES-CTR does not use padding) =====

  // ===== Utility Functions =====

  arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Extract base64 content from PEM format (removes headers)
   */
  private pemToBase64(pem: string): string {
    return pem
      .replace(/-----BEGIN.*?-----/g, '')
      .replace(/-----END.*?-----/g, '')
      .replace(/\s/g, '');
  }

  base64ToArrayBuffer(base64: string): ArrayBuffer {
    // Remove PEM headers if present
    const cleanBase64 = this.pemToBase64(base64);
    const binaryString = atob(cleanBase64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  uint8ArrayToBase64(array: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < array.byteLength; i++) {
      binary += String.fromCharCode(array[i]);
    }
    return btoa(binary);
  }

  base64ToUint8Array(base64: string): Uint8Array {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }

  arrayBufferToHex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  hexToArrayBuffer(hex: string): ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes.buffer;
  }

  async readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as ArrayBuffer);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  }

  // ===== Key Session Management =====

  /**
   * Desbloquea y carga la clave privada en memoria usando la contraseña del usuario
   */
  async unlockPrivateKey(password: string): Promise<void> {
    const encryptedPrivateKey = localStorage.getItem('encryptedPrivateKey');
    const keyDerivationParams = localStorage.getItem('keyDerivationParams');
    const publicKeyPEM = localStorage.getItem('publicKey');

    console.log('[CryptoService] Unlock attempt:', {
      hasEncryptedKey: !!encryptedPrivateKey,
      hasParams: !!keyDerivationParams,
      hasPublicKey: !!publicKeyPEM,
      paramsRaw: keyDerivationParams
    });

    if (!encryptedPrivateKey || !keyDerivationParams) {
      throw new Error('No se encontraron las claves del usuario');
    }

    // Parse derivation params with error handling
    let params;
    try {
      params = JSON.parse(keyDerivationParams);
      console.log('[CryptoService] Parsed params:', params);

      // Check if params is double-encoded (string instead of object)
      if (typeof params === 'string') {
        console.warn('[CryptoService] params is double-encoded, parsing again');
        params = JSON.parse(params);
      }
    } catch (error) {
      console.error('[CryptoService] Error parsing keyDerivationParams:', error);
      console.error('[CryptoService] Invalid JSON:', keyDerivationParams);
      throw new Error('Parámetros de derivación de clave inválidos. Por favor, cierra sesión y vuelve a iniciar.');
    }

    // Decrypt private key
    // Uses AES-CTR with counter parameter
    const privateKeyPEM = await this.decryptPrivateKey(
      encryptedPrivateKey,
      password,
      params.salt,
      params.counter  // Counter for AES-CTR mode
    );

    // Import keys into memory
    this.privateKeyCache = await this.importPrivateKey(privateKeyPEM);

    if (publicKeyPEM) {
      this.publicKeyCache = await this.importPublicKey(publicKeyPEM);
    }

    // También importar las claves como RSA-PSS para firma digital
    try {
      this.signingPrivateKeyCache = await this.importPrivateKeyForSigning(privateKeyPEM);
      if (publicKeyPEM) {
        this.signingPublicKeyCache = await this.importPublicKeyForSigning(publicKeyPEM);
      }
      console.log('[CryptoService] Signing keys imported successfully');
    } catch (error) {
      console.error('[CryptoService] Error importing signing keys:', error);
      // No es crítico si falla, pero log el error
    }

    console.log('[CryptoService] Private key unlocked successfully');
  }

  /**
   * Verifica si la clave privada está desbloqueada
   */
  isUnlocked(): boolean {
    return this.privateKeyCache !== null;
  }

  /**
   * Obtiene la clave privada desde el caché (requiere unlock previo)
   */
  getPrivateKey(): CryptoKey {
    if (!this.privateKeyCache) {
      throw new Error('Clave privada no desbloqueada. Llama a unlockPrivateKey() primero.');
    }
    return this.privateKeyCache;
  }

  /**
   * Obtiene la clave pública desde el caché
   */
  async getPublicKey(): Promise<CryptoKey> {
    if (!this.publicKeyCache) {
      const publicKeyPEM = localStorage.getItem('publicKey');
      if (!publicKeyPEM) {
        throw new Error('No se encontró la clave pública');
      }
      this.publicKeyCache = await this.importPublicKey(publicKeyPEM);
    }
    return this.publicKeyCache;
  }

  /**
   * Limpia las claves de la memoria (logout)
   */
  clearKeyCache(): void {
    this.privateKeyCache = null;
    this.publicKeyCache = null;
    this.signingPrivateKeyCache = null;
    this.signingPublicKeyCache = null;
  }
}
