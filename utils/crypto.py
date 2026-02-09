"""
Utilidades criptográficas para el sistema de protección de información
Implementa AES-256, RSA-4096, PBKDF2, SHA-256 y firmas digitales
"""

import os
import base64
import hashlib
import secrets
import json
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type

class CryptoManager:
    """Gestor centralizado de operaciones criptográficas"""
    
    def __init__(self):
        self.rsa_key_size = 4096  # RSA-4096 para máxima seguridad
        self.aes_key_size = 32    # AES-256
        # Argon2id parameters (memory-hard KDF)
        self.argon2_time_cost = 3
        self.argon2_memory_cost = 65536  # 64 MB
        self.argon2_parallelism = 4
        self.argon2_hash_len = 32
        
    def generate_rsa_keypair(self) -> Tuple[str, str]:
        """
        Generar par de claves RSA-4096
        Retorna: (private_key_pem, public_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size
        )
        
        public_key = private_key.public_key()
        
        # Serializar claves
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    def encrypt_private_key(self, private_key_pem: str, password: str, salt: bytes = None) -> Tuple[str, Dict]:
        """
        Cifrar clave privada con contraseña usando Argon2id + AES-256-CTR
        Compatible con el formato del frontend (AES-CTR con counter separado)
        Retorna: (encrypted_key_b64, derivation_params)
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Derivar clave de cifrado usando Argon2id
        derived_key = hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=self.argon2_time_cost,
            memory_cost=self.argon2_memory_cost,
            parallelism=self.argon2_parallelism,
            hash_len=self.aes_key_size,
            type=Type.ID  # Argon2id (hybrid mode)
        )
        
        # Generar counter aleatorio para AES-CTR (nonce de 128 bits)
        counter = secrets.token_bytes(16)  # 128-bit nonce
        
        # Cifrar con AES-256-CTR (mismo método que frontend)
        # CTR no requiere padding
        cipher = Cipher(
            algorithms.AES(derived_key),
            modes.CTR(counter)
        )
        encryptor = cipher.encryptor()
        
        # Cifrar (sin padding)
        private_key_bytes = private_key_pem.encode('utf-8')
        encrypted_key = encryptor.update(private_key_bytes) + encryptor.finalize()
        encrypted_b64 = base64.b64encode(encrypted_key).decode('utf-8')
        
        # Parámetros para derivación posterior (incluye counter separado)
        derivation_params = {
            'algorithm': 'Argon2id',
            'time_cost': self.argon2_time_cost,
            'memory_cost': self.argon2_memory_cost,
            'parallelism': self.argon2_parallelism,
            'salt': base64.b64encode(salt).decode('utf-8'),
            'counter': base64.b64encode(counter).decode('utf-8'),  # Counter en lugar de IV
            'hash_len': self.aes_key_size
        }
        
        return encrypted_b64, derivation_params
    
    def decrypt_private_key(self, encrypted_key_b64: str, password: str, derivation_params: Dict) -> str:
        """
        Descifrar clave privada usando los parámetros de derivación
        Usa AES-CTR (sin padding)
        """
        salt = base64.b64decode(derivation_params['salt'])
        
        # Derivar la misma clave usando Argon2id
        derived_key = hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=derivation_params.get('time_cost', self.argon2_time_cost),
            memory_cost=derivation_params.get('memory_cost', self.argon2_memory_cost),
            parallelism=derivation_params.get('parallelism', self.argon2_parallelism),
            hash_len=derivation_params.get('hash_len', self.aes_key_size),
            type=Type.ID
        )
        
        # Verificar que tiene counter (requerido para AES-CTR)
        if 'counter' not in derivation_params:
            raise ValueError('Counter requerido para AES-CTR. Base de datos debe migrarse.')
        
        # AES-CTR con counter separado
        counter = base64.b64decode(derivation_params['counter'])
        encrypted_key = base64.b64decode(encrypted_key_b64)
        
        # Descifrar con AES-CTR (sin padding)
        cipher = Cipher(
            algorithms.AES(derived_key),
            modes.CTR(counter)
        )
        decryptor = cipher.decryptor()
        private_key_pem = (decryptor.update(encrypted_key) + decryptor.finalize()).decode('utf-8')
        
        return private_key_pem
    
    def generate_aes_key(self) -> bytes:
        """Generar clave AES-256 aleatoria"""
        return secrets.token_bytes(self.aes_key_size)
    
    def encrypt_file_aes(self, file_content: bytes, aes_key: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """
        Cifrar archivo con AES-256-CTR
        Retorna: (encrypted_content, aes_key, counter)
        """
        if aes_key is None:
            aes_key = self.generate_aes_key()
        
        # Generar counter aleatorio (nonce de 128 bits)
        counter = secrets.token_bytes(16)
        
        # Crear cifrador con AES-CTR (sin padding)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(counter))
        encryptor = cipher.encryptor()
        
        # Cifrar (sin padding)
        encrypted_content = encryptor.update(file_content) + encryptor.finalize()
        
        return encrypted_content, aes_key, counter
    
    def decrypt_file_aes(self, encrypted_content: bytes, aes_key: bytes, counter: bytes) -> bytes:
        """
        Descifrar archivo con AES-256-CTR
        """
        # Crear descifrador con AES-CTR (sin padding)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(counter))
        decryptor = cipher.decryptor()
        
        # Descifrar (sin remover padding)
        original_content = decryptor.update(encrypted_content) + decryptor.finalize()
        
        return original_content
    
    def encrypt_aes_key_rsa(self, aes_key: bytes, public_key_pem: str) -> str:
        """
        Cifrar clave AES con RSA usando clave pública
        """
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted_aes_key).decode('utf-8')
    
    def decrypt_aes_key_rsa(self, encrypted_aes_key_b64: str, private_key_pem: str) -> bytes:
        """
        Descifrar clave AES con RSA usando clave privada
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
        
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
        
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return aes_key
    
    def sign_data(self, data: bytes, private_key_pem: str) -> str:
        """
        Firmar datos con RSA-PSS
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
        
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, data: bytes, signature_b64: str, public_key_pem: str) -> bool:
        """
        Verificar firma digital RSA-PSS
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            signature = base64.b64decode(signature_b64)
            
            print(f"[DEBUG verify_signature]:")
            print(f"  - Data to verify: {data[:50]}")
            print(f"  - Signature bytes: {len(signature)}")
            print(f"  - Public key type: {type(public_key)}")
            
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.AUTO  # Auto-detect salt length from signature
                ),
                hashes.SHA256()
            )
            print(f"[DEBUG] Signature verification SUCCESS")
            return True
        except Exception as e:
            print(f"[DEBUG] Signature verification FAILED: {type(e).__name__}: {str(e)}")
            return False
    
    def calculate_file_hash(self, file_content: bytes) -> str:
        """
        Calcular hash SHA-256 del archivo
        """
        return hashlib.sha256(file_content).hexdigest()
    
    def verify_file_integrity(self, file_content: bytes, expected_hash: str) -> bool:
        """
        Verificar integridad del archivo comparando hashes
        """
        actual_hash = self.calculate_file_hash(file_content)
        return actual_hash == expected_hash
    
    def secure_random_string(self, length: int = 32) -> str:
        """
        Generar string aleatorio seguro para sales, tokens, etc.
        """
        return secrets.token_hex(length)
    
    def derive_key_pbkdf2(self, password: str, salt: bytes, iterations: int = None, key_length: int = 32) -> bytes:
        """
        Derivar clave usando PBKDF2-SHA512
        """
        if iterations is None:
            iterations = self.pbkdf2_iterations
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=key_length,
            salt=salt,
            iterations=iterations,
        )
        
        return kdf.derive(password.encode())

class FileEncryption:
    """Clase especializada para el cifrado completo de archivos"""
    
    def __init__(self, crypto_manager: CryptoManager = None):
        self.crypto = crypto_manager or CryptoManager()
    
    def encrypt_file_for_user(self, file_content: bytes, user_public_key: str, 
                             private_key_for_signing: str = None) -> Dict[str, Any]:
        """
        Cifrar archivo completo para un usuario específico
        Incluye: cifrado AES + cifrado de clave AES con RSA + firma digital
        """
        # 1. Calcular hash del archivo original
        file_hash = self.crypto.calculate_file_hash(file_content)
        
        # 2. Cifrar archivo con AES-256
        encrypted_content, aes_key, iv = self.crypto.encrypt_file_aes(file_content)
        
        # 3. Cifrar clave AES con la clave pública del usuario
        encrypted_aes_key = self.crypto.encrypt_aes_key_rsa(aes_key, user_public_key)
        
        # 4. Combinar IV + contenido cifrado
        combined_encrypted = iv + encrypted_content
        
        # 5. Calcular hash del contenido cifrado
        encrypted_hash = self.crypto.calculate_file_hash(combined_encrypted)
        
        # 6. Firmar el hash del archivo original (si se proporciona clave privada)
        digital_signature = None
        if private_key_for_signing:
            digital_signature = self.crypto.sign_data(file_hash.encode(), private_key_for_signing)
        
        return {
            'encrypted_content': combined_encrypted,
            'encrypted_aes_key': encrypted_aes_key,
            'file_hash': file_hash,
            'encrypted_hash': encrypted_hash,
            'digital_signature': digital_signature
        }
    
    def decrypt_file_for_user(self, encrypted_data: Dict[str, Any], user_private_key: str) -> bytes:
        """
        Descifrar archivo completo para un usuario
        """
        # 1. Extraer IV y contenido cifrado
        combined_encrypted = encrypted_data['encrypted_content']
        iv = combined_encrypted[:16]
        encrypted_content = combined_encrypted[16:]
        
        # 2. Descifrar clave AES con la clave privada del usuario
        aes_key = self.crypto.decrypt_aes_key_rsa(
            encrypted_data['encrypted_aes_key'], 
            user_private_key
        )
        
        # 3. Descifrar archivo con AES
        file_content = self.crypto.decrypt_file_aes(encrypted_content, aes_key, iv)
        
        # 4. Verificar integridad
        if not self.crypto.verify_file_integrity(file_content, encrypted_data['file_hash']):
            raise ValueError("Error de integridad: el archivo ha sido modificado")
        
        return file_content

# Instancia global para uso en la aplicación
crypto_manager = CryptoManager()
file_encryption = FileEncryption(crypto_manager)
