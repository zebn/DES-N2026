"""
Utilidades para autenticación de doble factor (2FA)
Implementa TOTP (Time-based One-Time Password) y HOTP (HMAC-based One-Time Password)
"""

import base64
import secrets
import time
import hmac
import hashlib
import struct
import qrcode
import io
from typing import Tuple, Optional
from urllib.parse import quote

class TOTPManager:
    """Gestor de TOTP (Time-based One-Time Password)"""
    
    def __init__(self, issuer: str = "Protección Información", time_step: int = 30, digits: int = 6):
        self.issuer = issuer
        self.time_step = time_step  # Ventana de tiempo en segundos
        self.digits = digits        # Número de dígitos del código
        self.window = 1            # Ventana de tolerancia (±1 período)
    
    def generate_secret(self) -> str:
        """
        Generar secreto base32 aleatorio para TOTP
        """
        # 20 bytes = 160 bits de entropía (recomendado por RFC 6238)
        random_bytes = secrets.token_bytes(20)
        secret = base64.b32encode(random_bytes).decode('utf-8').rstrip('=')
        return secret
    
    def get_totp_token(self, secret: str, timestamp: Optional[int] = None) -> str:
        """
        Generar código TOTP para un momento específico
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # Calcular contador basado en tiempo
        counter = timestamp // self.time_step
        
        return self._generate_hotp(secret, counter)
    
    def verify_totp_token(self, secret: str, token: str, timestamp: Optional[int] = None) -> bool:
        """
        Verificar código TOTP con ventana de tolerancia
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # Probar en la ventana de tiempo actual y ±window períodos
        for offset in range(-self.window, self.window + 1):
            test_time = timestamp + (offset * self.time_step)
            expected_token = self.get_totp_token(secret, test_time)
            
            if self._constant_time_compare(token, expected_token):
                return True
        
        return False
    
    def generate_provisioning_uri(self, secret: str, account_name: str, issuer: Optional[str] = None) -> str:
        """
        Generar URI para configurar TOTP en apps como Google Authenticator
        """
        if issuer is None:
            issuer = self.issuer
        
        # Formato: otpauth://totp/Issuer:AccountName?secret=SECRET&issuer=Issuer
        uri = f"otpauth://totp/{quote(issuer)}:{quote(account_name)}"
        uri += f"?secret={secret}"
        uri += f"&issuer={quote(issuer)}"
        uri += f"&algorithm=SHA1"
        uri += f"&digits={self.digits}"
        uri += f"&period={self.time_step}"
        
        return uri
    
    def generate_qr_code(self, secret: str, account_name: str, issuer: Optional[str] = None) -> bytes:
        """
        Generar código QR para configuración de TOTP
        Retorna imagen PNG como bytes
        """
        uri = self.generate_provisioning_uri(secret, account_name, issuer)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convertir a bytes
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return img_buffer.getvalue()
    
    def _generate_hotp(self, secret: str, counter: int) -> str:
        """
        Generar código HOTP (usado internamente por TOTP)
        """
        # Decodificar secreto base32
        try:
            key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
        except Exception:
            raise ValueError("Secreto TOTP inválido")
        
        # Convertir contador a bytes (big-endian)
        counter_bytes = struct.pack('>Q', counter)
        
        # Calcular HMAC-SHA1
        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        
        # Aplicar truncamiento dinámico
        offset = hmac_hash[-1] & 0x0f
        truncated = struct.unpack('>I', hmac_hash[offset:offset + 4])[0]
        truncated &= 0x7fffffff
        
        # Generar código de N dígitos
        token = str(truncated % (10 ** self.digits))
        return token.zfill(self.digits)
    
    def _constant_time_compare(self, a: str, b: str) -> bool:
        """
        Comparación de tiempo constante para evitar ataques de temporización
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0

class HOTPManager:
    """Gestor de HOTP (HMAC-based One-Time Password)"""
    
    def __init__(self, digits: int = 6, window: int = 3):
        self.digits = digits
        self.window = window  # Ventana de sincronización
    
    def generate_secret(self) -> str:
        """
        Generar secreto base32 aleatorio para HOTP
        """
        random_bytes = secrets.token_bytes(20)
        secret = base64.b32encode(random_bytes).decode('utf-8').rstrip('=')
        return secret
    
    def get_hotp_token(self, secret: str, counter: int) -> str:
        """
        Generar código HOTP para un contador específico
        """
        # Decodificar secreto base32
        try:
            key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
        except Exception:
            raise ValueError("Secreto HOTP inválido")
        
        # Convertir contador a bytes (big-endian)
        counter_bytes = struct.pack('>Q', counter)
        
        # Calcular HMAC-SHA1
        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        
        # Aplicar truncamiento dinámico
        offset = hmac_hash[-1] & 0x0f
        truncated = struct.unpack('>I', hmac_hash[offset:offset + 4])[0]
        truncated &= 0x7fffffff
        
        # Generar código de N dígitos
        token = str(truncated % (10 ** self.digits))
        return token.zfill(self.digits)
    
    def verify_hotp_token(self, secret: str, token: str, counter: int) -> Tuple[bool, int]:
        """
        Verificar código HOTP con ventana de sincronización
        Retorna: (is_valid, new_counter)
        """
        # Probar en la ventana de sincronización
        for test_counter in range(counter, counter + self.window + 1):
            expected_token = self.get_hotp_token(secret, test_counter)
            
            if self._constant_time_compare(token, expected_token):
                return True, test_counter + 1  # Incrementar contador
        
        return False, counter  # No válido, mantener contador
    
    def _constant_time_compare(self, a: str, b: str) -> bool:
        """
        Comparación de tiempo constante para evitar ataques de temporización
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0

class TwoFactorAuth:
    """Clase principal para manejo de autenticación de doble factor"""
    
    def __init__(self, issuer: str = "Protección Información"):
        self.totp = TOTPManager(issuer)
        self.hotp = HOTPManager()
        self.issuer = issuer
    
    def setup_totp_for_user(self, user_email: str) -> Tuple[str, str, bytes]:
        """
        Configurar TOTP para un usuario
        Retorna: (secret, provisioning_uri, qr_code_png)
        """
        secret = self.totp.generate_secret()
        uri = self.totp.generate_provisioning_uri(secret, user_email)
        qr_code = self.totp.generate_qr_code(secret, user_email)
        
        return secret, uri, qr_code
    
    def verify_totp_setup(self, secret: str, user_token: str) -> bool:
        """
        Verificar que el usuario configuró TOTP correctamente
        """
        return self.totp.verify_totp_token(secret, user_token)
    
    def verify_totp_login(self, secret: str, user_token: str) -> bool:
        """
        Verificar código TOTP durante el login
        """
        return self.totp.verify_totp_token(secret, user_token)
    
    def setup_hotp_for_user(self) -> str:
        """
        Configurar HOTP para un usuario
        Retorna: secret
        """
        return self.hotp.generate_secret()
    
    def verify_hotp_operation(self, secret: str, user_token: str, current_counter: int) -> Tuple[bool, int]:
        """
        Verificar código HOTP para operaciones firmadas
        Retorna: (is_valid, new_counter)
        """
        return self.hotp.verify_hotp_token(secret, user_token, current_counter)
    
    def generate_backup_codes(self, count: int = 10) -> list:
        """
        Generar códigos de respaldo para cuando no se puede usar 2FA
        """
        backup_codes = []
        for _ in range(count):
            # Generar código de 8 caracteres alfanuméricos
            code = secrets.token_hex(4).upper()
            backup_codes.append(code)
        
        return backup_codes

# Instancia global para uso en la aplicación
two_factor_auth = TwoFactorAuth()
