#!/usr/bin/env python3
"""
Cliente de línea de comandos para el Sistema de Protección de Información
"""


import os
import sys
import json
import requests
import getpass
from pathlib import Path
from typing import Optional, Dict
import base64
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import secrets
import urllib3

# Deshabilitar advertencias de SSL para certificados autofirmados en desarrollo
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cargar variables de entorno desde .env
# Buscar .env en el directorio del script, no en el directorio actual
script_dir = Path(__file__).parent
dotenv_path = script_dir / '.env'
load_dotenv(dotenv_path=dotenv_path)
print(f"Ruta del archivo .env: {dotenv_path}")
print(f"SERVER_URL: {os.environ.get('SERVER_URL')}")


class SecureClient:
    """Cliente para interactuar con el servidor de protección"""
    
    def __init__(self, base_url: Optional[str] = None):
            self.base_url = base_url or os.environ.get('SERVER_URL', 'https://localhost:5001')
            self.token = None
            self.refresh_token = None
            self.request_timeout = int(os.environ.get('REQUEST_TIMEOUT', '30'))
            self.connection_timeout = int(os.environ.get('CONNECTION_TIMEOUT', '10'))
            self.debug = os.environ.get('CLIENT_DEBUG', 'False').lower() in ('true', '1', 'yes')
            # Файл конфигурации в той же директории, что и client.py
            config_file_name = os.environ.get('CONFIG_FILE', '.secure_client_config.json')
            self.config_file = Path(__file__).parent / config_file_name
            if self.debug:
                print(f"[DEBUG] Archivo de configuración: {self.config_file}")
            self.load_config()
    
    def load_config(self):
        """Cargar configuración guardada"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.token = config.get('token')
                    self.refresh_token = config.get('refresh_token')
                    # No cargar base_url del config - siempre usar .env
                    # self.base_url ya está configurado desde las variables de entorno
            except Exception as e:
                print(f"⚠️  Error cargando configuración: {e}")
    
    def save_config(self):
        """Guardar configuración"""
        try:
            config = {
                'token': self.token,
                'refresh_token': self.refresh_token,
                # No guardar base_url - siempre usar desde .env
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Establecer permisos (funciona diferente en Windows)
            try:
                if os.name != 'nt':  # Unix/Linux/Mac
                    os.chmod(self.config_file, 0o600)
                else:  # Windows
                    import stat
                    os.chmod(self.config_file, stat.S_IREAD | stat.S_IWRITE)
            except Exception as chmod_error:
                if self.debug:
                    print(f"⚠️  Advertencia: no se pudieron establecer permisos del archivo: {chmod_error}")
            
            if self.debug:
                print(f"✅ Configuración guardada en: {self.config_file}")
        except Exception as e:
            print(f"⚠️  Error guardando configuración: {e}")
    
    def get_headers(self) -> dict:
        """Obtener headers con token de autenticación"""
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers
    
    def generate_rsa_keypair(self):
        """Generar par de claves RSA-4096"""
        if self.debug:
            print("[DEBUG] Generando par de claves RSA-4096...")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
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
        
        if self.debug:
            print("[DEBUG] Claves RSA generadas exitosamente")
        
        return private_pem, public_pem
    
    def encrypt_private_key(self, private_key_pem: str, password: str):
        """Cifrar clave privada con contraseña usando PBKDF2 + AES-256"""
        if self.debug:
            print("[DEBUG] Cifrando clave privada...")
        
        salt = secrets.token_bytes(32)
        
        # Derivar clave de cifrado usando PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=200000,
        )
        derived_key = kdf.derive(password.encode())
        
        # Cifrar con Fernet (AES-256-CBC + HMAC)
        fernet_key = base64.urlsafe_b64encode(derived_key)
        fernet = Fernet(fernet_key)
        
        # Fernet.encrypt() ya devuelve un token en base64 (bytes)
        encrypted_token = fernet.encrypt(private_key_pem.encode())
        # Convertir bytes a string (NO hacer base64 adicional)
        encrypted_token_str = encrypted_token.decode('utf-8')
        
        # Parámetros para derivación posterior
        derivation_params = {
            'algorithm': 'PBKDF2',
            'hash': 'SHA-512',
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iterations': 200000,
            'key_length': 32
        }
        
        if self.debug:
            print("[DEBUG] Clave privada cifrada exitosamente")
            print(f"[DEBUG] Token Fernet (preview): {encrypted_token_str[:50]}...")
        
        return encrypted_token_str, derivation_params
    
    def decrypt_private_key(self, encrypted_private_key_b64: str, password: str, derivation_params: dict):
        """
        Descifrar clave privada con contraseña usando PBKDF2 + Fernet
        
        Args:
            encrypted_private_key_b64: Clave privada cifrada (Fernet token)
            password: Contraseña del usuario
            derivation_params: Parámetros de derivación (salt, iterations, etc.)
            
        Returns:
            str: Clave privada en formato PEM
        """
        if self.debug:
            print("[DEBUG] Descifrando clave privada...")
        
        # Obtener salt de los parámetros
        salt = base64.b64decode(derivation_params['salt'])
        iterations = derivation_params['iterations']
        
        if self.debug:
            print(f"[DEBUG] Salt: {derivation_params['salt'][:50]}...")
            print(f"[DEBUG] Iterations: {iterations}")
        
        # Derivar clave de cifrado usando PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        derived_key = kdf.derive(password.encode())
        
        if self.debug:
            print(f"[DEBUG] Derived key: {base64.urlsafe_b64encode(derived_key).decode()[:50]}...")
        
        # Descifrar con Fernet
        fernet_key = base64.urlsafe_b64encode(derived_key)
        fernet = Fernet(fernet_key)
        
        # encrypted_private_key_b64 es un Fernet token (string en base64)
        # Fernet.decrypt() espera bytes, así que convertimos string -> bytes
        try:
            if self.debug:
                print(f"[DEBUG] Fernet token type: {type(encrypted_private_key_b64)}")
                print(f"[DEBUG] Fernet token preview: {encrypted_private_key_b64[:50]}...")
            
            # Convertir string a bytes y descifrar
            private_key_pem = fernet.decrypt(encrypted_private_key_b64.encode()).decode('utf-8')
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error en Fernet.decrypt:")
                print(f"[DEBUG] Error type: {type(e).__name__}")
                print(f"[DEBUG] Error message: {str(e)}")
                import traceback
                traceback.print_exc()
            raise
        
        if self.debug:
            print("[DEBUG] Clave privada descifrada exitosamente")
            print(f"[DEBUG] Private key preview: {private_key_pem[:80]}...")
        
        return private_key_pem
    
    def sign_file_hash(self, file_hash: str, private_key_pem: str):
        """
        Firmar hash de archivo con clave privada RSA-PSS
        
        Args:
            file_hash: Hash SHA-256 del archivo (hex string)
            private_key_pem: Clave privada RSA en formato PEM
            
        Returns:
            str: Firma digital en base64
        """
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.backends import default_backend
        
        if self.debug:
            print("[DEBUG] Firmando archivo con RSA-PSS...")
        
        # Cargar clave privada
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Firmar el hash con RSA-PSS
        signature = private_key.sign(
            file_hash.encode(),  # El servidor envía el hash como bytes del string hex
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        if self.debug:
            print("[DEBUG] Firma digital RSA-PSS generada")
        
        return signature_b64
    
    def encrypt_file_content(self, file_content: bytes, user_public_key: str):
        """
        Cifrar contenido de archivo con AES-256 y cifrar la clave AES con RSA
        
        Args:
            file_content: Contenido del archivo en bytes
            user_public_key: Clave pública RSA del usuario en formato PEM
            
        Returns:
            tuple: (encrypted_content_b64, encrypted_aes_key_b64, digital_signature_b64)
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.backends import default_backend
        import hashlib
        
        if self.debug:
            print("[DEBUG] Cifrando archivo con AES-256...")
        
        # 1. Generar clave AES-256 aleatoria (32 bytes)
        aes_key = secrets.token_bytes(32)
        
        # 2. Generar IV aleatorio para AES-CBC (16 bytes)
        iv = secrets.token_bytes(16)
        
        # 3. Padding PKCS7 para el contenido
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(file_content) + padder.finalize()
        
        # 4. Cifrar con AES-256-CBC
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
        
        # 5. Concatenar IV + contenido cifrado y codificar en base64
        encrypted_with_iv = iv + encrypted_content
        encrypted_content_b64 = base64.b64encode(encrypted_with_iv).decode('utf-8')
        
        if self.debug:
            print(f"[DEBUG] Archivo cifrado: {len(encrypted_content)} bytes")
        
        # 6. Cargar clave pública RSA del usuario
        public_key = serialization.load_pem_public_key(
            user_public_key.encode('utf-8'),
            backend=default_backend()
        )
        
        # 7. Cifrar clave AES con RSA-OAEP
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
        
        if self.debug:
            print("[DEBUG] Clave AES cifrada con RSA")
        
        return encrypted_content_b64, encrypted_aes_key_b64
    
    def decrypt_file_content(self, encrypted_content_b64: str, encrypted_aes_key_b64: str, private_key_pem: str):
        """
        Descifrar contenido de archivo con RSA + AES-256
        
        Args:
            encrypted_content_b64: Contenido cifrado en base64 (IV + contenido)
            encrypted_aes_key_b64: Clave AES cifrada con RSA en base64
            private_key_pem: Clave privada RSA en formato PEM
            
        Returns:
            bytes: Contenido descifrado del archivo
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.backends import default_backend
        
        if self.debug:
            print("[DEBUG] Descifrando archivo...")
        
        # 1. Cargar clave privada RSA
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # 2. Descifrar clave AES con RSA-OAEP
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        if self.debug:
            print(f"[DEBUG] Clave AES descifrada: {len(aes_key)} bytes")
        
        # 3. Decodificar contenido cifrado (IV + contenido)
        encrypted_with_iv = base64.b64decode(encrypted_content_b64)
        
        # 4. Extraer IV (primeros 16 bytes) y contenido cifrado
        iv = encrypted_with_iv[:16]
        encrypted_content = encrypted_with_iv[16:]
        
        if self.debug:
            print(f"[DEBUG] IV extraído: {len(iv)} bytes")
            print(f"[DEBUG] Contenido cifrado: {len(encrypted_content)} bytes")
        
        # 5. Descifrar con AES-256-CBC
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_content = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # 6. Eliminar padding PKCS7
        unpadder = sym_padding.PKCS7(128).unpadder()
        file_content = unpadder.update(padded_content) + unpadder.finalize()
        
        if self.debug:
            print(f"[DEBUG] Archivo descifrado: {len(file_content)} bytes")
        
        return file_content
    
    def make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, files: Optional[Dict] = None) -> Optional[Dict]:
        """Realizar petición HTTP al servidor"""
        url = f"{self.base_url}{endpoint}"

        if self.debug:
            print(f"[DEBUG] {method} {url}")
            if self.token:
                print(f"[DEBUG] Token presente: {self.token[:50]}..." if len(self.token) > 50 else f"[DEBUG] Token: {self.token}")

        try:
            # Deshabilitar verificación SSL para certificados autofirmados en desarrollo
            verify_ssl = not self.base_url.startswith('https://localhost')
            
            # if self.debug and not verify_ssl:
            #     print("[DEBUG] Verificación SSL deshabilitada para localhost")
            
            if files:
                response = requests.request(
                    method, url,
                    headers={'Authorization': f'Bearer {self.token}'},
                    files=files,
                    data=data,
                    timeout=(self.connection_timeout, self.request_timeout),
                    verify=verify_ssl
                )
            else:
                response = requests.request(
                    method, url,
                    headers=self.get_headers(),
                    json=data,
                    timeout=(self.connection_timeout, self.request_timeout),
                    verify=verify_ssl
                )

            if self.debug:
                print(f"[DEBUG] Status: {response.status_code}")

            # Solo tratar 401 como token expirado si ya tenemos un token y no es login
            if response.status_code == 401 and self.token and '/login' not in endpoint:
                if self.debug:
                    print(f"[DEBUG] Respuesta 401: {response.text}")
                print("❌ Token expirado. Por favor, inicia sesión nuevamente.")
                self.token = None
                self.save_config()
                return None

            try:
                return response.json() if response.content else {}
            except:
                if self.debug:
                    print(f"[DEBUG] No se pudo parsear JSON. Respuesta: {response.text}")
                return {}
        
        except requests.exceptions.ConnectionError:
            print(f"❌ Error de conexión. ¿El servidor está corriendo en {self.base_url}?")
            return None
        except requests.exceptions.Timeout:
            print(f"❌ Tiempo de espera agotado. El servidor no responde.")
            return None
        except Exception as e:
            print(f"❌ Error en la petición: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return None
    
    def server_info(self):
        """Obtener información del servidor"""
        print("\n🔐 Consultando información del servidor...\n")
        response = self.make_request('GET', '/')
        
        if response:
            print(f"📋 Nombre: {response.get('name')}")
            print(f"📌 Versión: {response.get('version')}")
            print(f"📝 Descripción: {response.get('description')}")
            print("\n🛡️  Características de seguridad:")
            for feature in response.get('security_features', []):
                print(f"   • {feature}")
            print(f"\n🔒 Niveles de clasificación: {', '.join(response.get('classification_levels', []))}")
        
        return response
    
    def register(self):
        """Registrar nuevo usuario"""
        print("\n📝 REGISTRO DE NUEVO USUARIO\n")
        print("🔐 Generando claves RSA-4096 (esto puede tardar unos segundos)...\n")
        
        nombre = input("Nombre: ")
        apellidos = input("Apellidos: ")
        email = input("Email: ")
        telefono = input("Teléfono (opcional): ")
        password = getpass.getpass("Contraseña: ")
        password2 = getpass.getpass("Confirmar contraseña: ")
        
        if password != password2:
            print("❌ Las contraseñas no coinciden")
            return
        
        clearance = input("Nivel de autorización (RESTRICTED/CONFIDENTIAL/SECRET/TOP_SECRET) [CONFIDENTIAL]: ").upper()
        if not clearance:
            clearance = "CONFIDENTIAL"
        
        try:
            # Generar par de claves RSA-4096
            print("\n⏳ Generando par de claves RSA-4096...")
            private_key_pem, public_key_pem = self.generate_rsa_keypair()
            
            # Cifrar clave privada con la contraseña del usuario
            print("⏳ Cifrando clave privada con su contraseña...")
            encrypted_private_key, derivation_params = self.encrypt_private_key(private_key_pem, password)
            
            print("✅ Claves generadas y cifradas exitosamente\n")
            
            data = {
                'nombre': nombre,
                'apellidos': apellidos,
                'email': email,
                'telefono': telefono,
                'password': password,
                'clearance_level': clearance,
                'public_key': public_key_pem,
                'encrypted_private_key': encrypted_private_key,
                'key_derivation_params': json.dumps(derivation_params)
            }
            
            print("⏳ Enviando datos al servidor...")
            response = self.make_request('POST', '/api/auth/register', data)
            
            if response and not response.get('error'):
                print("\n✅ Usuario registrado exitosamente")
                print(f"👤 Usuario ID: {response.get('user', {}).get('id')}")
                print(f"🔒 Claves RSA-4096 generadas y almacenadas de forma segura")
            elif response:
                print(f"\n❌ Error: {response.get('error')}")
        
        except Exception as e:
            print(f"\n❌ Error durante el registro: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
    
    def login(self):
        """Iniciar sesión"""
        print("\n🔐 INICIO DE SESIÓN\n")

        email = input("Email: ")
        password = getpass.getpass("Contraseña: ")

        data = {
            'email': email,
            'password': password
        }

        response = self.make_request('POST', '/api/auth/login', data)

        # Si el servidor indica que se requiere 2FA
        if response and response.get('requires_2fa'):
            print("\n🔐 Este usuario tiene 2FA habilitado")
            totp_code = input("🔢 Ingrese código 2FA: ")

            # Reintentar login con el código 2FA
            data['totp_code'] = totp_code
            response = self.make_request('POST', '/api/auth/login', data)

        if response and response.get('access_token'):
            self.token = response['access_token']
            self.refresh_token = response.get('refresh_token')

            if self.debug:
                print(f"[DEBUG] Token recibido: {self.token[:50]}..." if len(self.token) > 50 else f"[DEBUG] Token: {self.token}")

            self.save_config()

            if self.debug:
                print(f"[DEBUG] Token guardado. Verificando...")
                print(f"[DEBUG] self.token está establecido: {bool(self.token)}")
                print(f"[DEBUG] Config guardado en: {self.config_file}")

            print("\n✅ Inicio de sesión exitoso")

            user = response.get('user', {})
            print(f"👤 Bienvenido: {user.get('nombre')} {user.get('apellidos')}")
            print(f"🔒 Nivel de autorización: {user.get('clearance_level')}")

        elif response:
            print(f"\n❌ Error: {response.get('error')}")
    
    def verify_2fa_login(self):
        """Verificar código 2FA durante login"""
        code = input("\n🔢 Ingrese código 2FA: ")
        
        data = {'code': code}
        response = self.make_request('POST', '/api/auth/verify-2fa-login', data)
        
        if response and response.get('access_token'):
            self.token = response['access_token']
            self.save_config()
            print("✅ Verificación 2FA exitosa")
        elif response:
            print(f"❌ Error: {response.get('error')}")
    
    def profile(self):
        """Ver perfil de usuario"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return
        
        print("\n👤 PERFIL DE USUARIO\n")
        response = self.make_request('GET', '/api/auth/profile')
        
        if response:
            # API devuelve {"user": {...}}
            user = response.get('user', response)  # fallback a response si no hay 'user'
            print(f"ID: {user.get('id')}")
            print(f"Nombre: {user.get('nombre')} {user.get('apellidos')}")
            print(f"Email: {user.get('email')}")
            print(f"Teléfono: {user.get('telefono', 'N/A')}")
            print(f"Nivel de autorización: {user.get('clearance_level')}")
            print(f"Rol: {'👑 Administrador' if user.get('is_admin') else '👤 Usuario'}")
            print(f"Estado: {'✅ Activo' if user.get('is_active') else '❌ Inactivo'}")
            print(f"2FA habilitado: {'Sí' if user.get('is_2fa_enabled') else 'No'}")
            print(f"Fecha de creación: {user.get('created_at')}")
            print(f"Último acceso: {user.get('last_login', 'N/A')}")
    
    def setup_2fa(self):
        """Configurar autenticación de dos factores"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return

        print("\n🔐 CONFIGURACIÓN 2FA\n")
        response = self.make_request('POST', '/api/auth/setup-2fa')

        if response and response.get('qr_code'):
            print("✅ 2FA configurado")
            print(f"\n📱 Secreto TOTP: {response.get('secret')}")
            print(f"🔗 URI: {response.get('setup_uri')}")
            print("\nEscanea este código QR con tu aplicación de autenticación:")
            print(f"(QR Code disponible como base64 en respuesta)")

            # Guardar QR en archivo
            qr_file = "qr_2fa.png"
            with open(qr_file, 'wb') as f:
                f.write(base64.b64decode(response['qr_code']))
            print(f"\n💾 Código QR guardado en: {qr_file}")

            print("\n⚠️  Ahora debes verificar el código para habilitar 2FA")
        elif response:
            print(f"\n❌ Error en setup: {response.get('error')}")
    
    def verify_2fa(self):
        """Verificar y habilitar 2FA"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return

        code = input("\n🔢 Ingrese código 2FA de su aplicación: ")

        data = {'totp_code': code}

        if self.debug:
            print(f"[DEBUG] Enviando datos: {data}")
            print(f"[DEBUG] Código ingresado: '{code}' (longitud: {len(code)})")

        response = self.make_request('POST', '/api/auth/verify-2fa', data)

        if self.debug and response:
            print(f"[DEBUG] Respuesta completa: {response}")

        if response and response.get('message'):
            print(f"\n✅ {response['message']}")
            if response.get('backup_codes'):
                print("\n🔑 Códigos de respaldo (guárdalos en un lugar seguro):")
                for i, code in enumerate(response['backup_codes'], 1):
                    print(f"   {i}. {code}")
        elif response:
            print(f"\n❌ Error: {response.get('error')}")
    
    def logout(self):
        """Cerrar sesión"""
        if self.debug:
            print(f"[DEBUG] Token actual: {self.token[:50] + '...' if self.token and len(self.token) > 50 else self.token}")
            print(f"[DEBUG] Config file: {self.config_file}")
            print(f"[DEBUG] Config file exists: {self.config_file.exists()}")

        if not self.token:
            print("❌ No hay sesión activa")
            return

        response = self.make_request('POST', '/api/auth/logout')

        self.token = None
        self.refresh_token = None
        self.save_config()

        print("\n✅ Sesión cerrada exitosamente")
    
    def upload_file(self):
        """Subir archivo cifrado al servidor"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return

        print("\n📤 SUBIR ARCHIVO\n")

        file_path = input("Ruta del archivo a subir: ").strip().strip('"').strip("'")

        if not os.path.exists(file_path):
            print(f"❌ El archivo no existe: {file_path}")
            return

        filename = os.path.basename(file_path)
        print(f"📄 Archivo: {filename}")

        title = input("Título del archivo: ").strip() or filename
        classification = input("Nivel de clasificación (RESTRICTED/CONFIDENTIAL/SECRET/TOP_SECRET) [CONFIDENTIAL]: ").strip().upper()
        if not classification:
            classification = "CONFIDENTIAL"

        description = input("Descripción (opcional): ").strip()

        try:
            # Leer archivo
            print("\n⏳ Leyendo archivo...")
            with open(file_path, 'rb') as f:
                file_content = f.read()

            file_size = len(file_content)
            print(f"📊 Tamaño: {file_size / 1024:.2f} KB ({file_size} bytes)")
            
            # Validar que el archivo no esté vacío
            if file_size == 0:
                print("⚠️  Advertencia: El archivo está vacío (0 bytes)")
                continue_upload = input("¿Desea continuar de todos modos? (s/N): ").strip().lower()
                if continue_upload != 's':
                    print("❌ Operación cancelada")
                    return
            
            # Detectar MIME type
            import mimetypes
            mime_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            
            # Calcular hash SHA-256
            print("🔐 Calculando hash...")
            import hashlib
            file_hash = hashlib.sha256(file_content).hexdigest()
            
            # Obtener clave pública del usuario desde su perfil
            print("⏳ Obteniendo clave pública del usuario...")
            profile_response = self.make_request('GET', '/api/auth/profile')
            
            if not profile_response:
                print("❌ Error: No se pudo obtener el perfil del usuario")
                return
            
            user = profile_response.get('user', profile_response)
            user_public_key = user.get('public_key')
            encrypted_private_key = user.get('encrypted_private_key')
            key_derivation_params_json = user.get('key_derivation_params')
            
            if not user_public_key or user_public_key == "DUMMY_PUBLIC_KEY":
                print("⚠️  NOTA: No se encontró clave pública RSA válida.")
                print("    El archivo se cifrará con AES pero la clave no será protegida.")
                use_real_encryption = False
            else:
                print("✅ Clave pública encontrada. Usando cifrado completo AES-256 + RSA-4096")
                use_real_encryption = True
            
            # Cifrar archivo
            print("🔐 Cifrando archivo...")
            
            if use_real_encryption:
                # Pedir contraseña para descifrar la clave privada
                print("\n🔑 Se requiere su contraseña para firmar el archivo")
                password = getpass.getpass("Contraseña: ")
                
                # Descifrar clave privada
                try:
                    key_derivation_params = json.loads(key_derivation_params_json)
                    private_key_pem = self.decrypt_private_key(
                        encrypted_private_key, 
                        password, 
                        key_derivation_params
                    )
                except Exception as e:
                    print(f"❌ Error al descifrar la clave privada:")
                    print(f"   Tipo: {type(e).__name__}")
                    print(f"   Mensaje: {str(e)}")
                    print("   Verifique que la contraseña sea correcta")
                    if self.debug:
                        import traceback
                        traceback.print_exc()
                    return
                
                # Cifrar archivo con AES-256 + RSA-OAEP
                encrypted_content_b64, encrypted_aes_key_b64 = \
                    self.encrypt_file_content(file_content, user_public_key)
                
                # Firmar el hash del archivo con la clave privada
                digital_signature_b64 = self.sign_file_hash(file_hash, private_key_pem)
                
            else:
                # Fallback: solo base64 (para usuarios sin clave RSA)
                encrypted_content_b64 = base64.b64encode(file_content).decode('utf-8')
                # Generar AES key dummy
                dummy_aes_key = base64.b64encode(b'DUMMY_AES_KEY_32_BYTES_NEEDED!').decode('utf-8')
                encrypted_aes_key_b64 = dummy_aes_key
                # Firma dummy
                digital_signature_b64 = base64.b64encode(hashlib.sha256(file_content).digest()).decode('utf-8')
            
            # Preparar datos JSON
            data = {
                'title': title,
                'original_filename': filename,
                'file_size': file_size,
                'mime_type': mime_type,
                'classification_level': classification,
                'encrypted_content': encrypted_content_b64,
                'encrypted_aes_key': encrypted_aes_key_b64,
                'file_hash': file_hash,
                'digital_signature': digital_signature_b64,
                'description': description
            }
            
            if self.debug:
                print(f"[DEBUG] Datos a enviar:")
                print(f"  - title: {title}")
                print(f"  - original_filename: {filename}")
                print(f"  - file_size: {file_size}")
                print(f"  - mime_type: {mime_type}")
                print(f"  - classification_level: {classification}")
                print(f"  - encrypted_content: {len(encrypted_content_b64)} chars")
                print(f"  - encrypted_aes_key: {len(encrypted_aes_key_b64)} chars")
                print(f"  - file_hash: {file_hash[:16]}...")
                print(f"  - using_real_encryption: {use_real_encryption}")

            print("⏳ Subiendo archivo al servidor...")
            response = self.make_request('POST', '/api/files/upload', data=data)

            if response and not response.get('error'):
                print("\n✅ Archivo subido exitosamente")
                print(f"📄 ID: {response.get('file_id')}")
                print(f"🔒 Clasificación: {classification}")
                print(f"🔐 Cifrado: {'AES-256 + RSA-4096' if use_real_encryption else 'Base64 (sin RSA)'}")
                print(f"#️⃣  Hash: {file_hash[:16]}...")
            elif response:
                print(f"\n❌ Error: {response.get('error')}")
            else:
                print("\n❌ Error: No se recibió respuesta del servidor")

        except Exception as e:
            print(f"❌ Error: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()

    def list_files(self):
        """Listar archivos del usuario"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return

        print("\n📂 MIS ARCHIVOS\n")
        response = self.make_request('GET', '/api/files/')

        if response and response.get('files'):
            files = response['files']
            print(f"Total de archivos: {len(files)}\n")

            for f in files:
                print(f"📄 {f.get('filename')}")
                print(f"   ID: {f.get('id')}")
                print(f"   Clasificación: {f.get('classification_level')}")
                print(f"   Tamaño: {f.get('file_size')} bytes")
                print(f"   Subido: {f.get('uploaded_at')}")
                print()
        elif response:
            print("No hay archivos")

    def get_file_info(self):
        """Obtener información detallada de un archivo"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return

        print("\n📋 INFORMACIÓN DE ARCHIVO\n")
        file_id = input("ID del archivo: ").strip()

        if not file_id:
            print("❌ ID inválido")
            return

        response = self.make_request('GET', f'/api/files/{file_id}')

        if response and not response.get('error'):
            print(f"\n📄 {response.get('filename')}")
            print(f"   ID: {response.get('id')}")
            print(f"   Clasificación: {response.get('classification_level')}")
            print(f"   Descripción: {response.get('description', 'N/A')}")
            print(f"   Tamaño: {response.get('file_size')} bytes")
            print(f"   Hash SHA-256: {response.get('file_hash')}")
            print(f"   Propietario: {response.get('owner_name')}")
            print(f"   Subido: {response.get('uploaded_at')}")
            print(f"   Última modificación: {response.get('updated_at')}")
        elif response:
            print(f"\n❌ Error: {response.get('error')}")

    def download_file(self):
        """Descargar archivo del servidor"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return

        print("\n📥 DESCARGAR ARCHIVO\n")
        file_id = input("ID del archivo: ").strip()

        if not file_id:
            print("❌ ID inválido")
            return

        response = self.make_request('POST', f'/api/files/{file_id}/download')

        if response and response.get('download_data'):
            try:
                download_data = response['download_data']
                filename = download_data.get('original_filename', f'file_{file_id}')
                
                print(f"\n📄 Archivo: {filename}")
                print(f"🔒 Clasificación: {download_data.get('classification_level')}")
                print(f"📦 Tamaño cifrado: {download_data.get('file_size')} bytes")
                
                # Preguntar si desea descifrar el archivo
                decrypt = input("\n¿Desea descifrar el archivo? (S/n): ").strip().lower()
                
                if decrypt == 'n':
                    # Guardar archivo cifrado
                    print("\n⚠️  Guardando archivo CIFRADO (no descifrado)")
                    encrypted_content = base64.b64decode(download_data['encrypted_content'])
                    
                    output_path = input(f"Guardar como [{filename}.encrypted]: ").strip()
                    if not output_path:
                        output_path = f"{filename}.encrypted"
                    
                    with open(output_path, 'wb') as f:
                        f.write(encrypted_content)
                    
                    print(f"\n✅ Archivo cifrado guardado: {output_path}")
                    print(f"📦 Tamaño: {len(encrypted_content)} bytes")
                    
                else:
                    # Descifrar archivo
                    print("\n🔑 Se requiere su contraseña para descifrar el archivo")
                    password = getpass.getpass("Contraseña: ")
                    
                    # Obtener perfil con clave privada cifrada
                    print("⏳ Obteniendo clave privada...")
                    profile_response = self.make_request('GET', '/api/auth/profile')
                    
                    if not profile_response:
                        print("❌ Error: No se pudo obtener el perfil del usuario")
                        return
                    
                    user = profile_response.get('user', profile_response)
                    encrypted_private_key = user.get('encrypted_private_key')
                    key_derivation_params_json = user.get('key_derivation_params')
                    
                    # Descifrar clave privada
                    try:
                        key_derivation_params = json.loads(key_derivation_params_json)
                        private_key_pem = self.decrypt_private_key(
                            encrypted_private_key,
                            password,
                            key_derivation_params
                        )
                    except Exception as e:
                        print(f"❌ Error al descifrar la clave privada: {e}")
                        print("   Verifique que la contraseña sea correcta")
                        return
                    
                    # Descifrar archivo con AES-256 + RSA-OAEP
                    try:
                        print("🔓 Descifrando archivo con AES-256 + RSA-4096...")
                        
                        decrypted_content = self.decrypt_file_content(
                            download_data['encrypted_content'],
                            download_data['encrypted_aes_key'],
                            private_key_pem
                        )
                        
                        # Guardar archivo descifrado
                        output_path = input(f"Guardar como [{filename}]: ").strip()
                        if not output_path:
                            output_path = filename
                        
                        with open(output_path, 'wb') as f:
                            f.write(decrypted_content)
                        
                        print(f"\n✅ Archivo descifrado exitosamente: {output_path}")
                        print(f"📄 Nombre original: {filename}")
                        print(f"📦 Tamaño descifrado: {len(decrypted_content)} bytes")
                        print(f"🔒 Clasificación: {download_data.get('classification_level')}")
                        print(f"#️⃣  Hash SHA-256: {download_data.get('file_hash')[:16]}...")
                        
                    except Exception as e:
                        print(f"❌ Error al descifrar el archivo: {e}")
                        if self.debug:
                            import traceback
                            traceback.print_exc()
                        print("\n⚠️  Guardando archivo cifrado como respaldo...")
                        
                        encrypted_content = base64.b64decode(download_data['encrypted_content'])
                        output_path = input(f"Guardar como [{filename}.encrypted]: ").strip()
                        if not output_path:
                            output_path = f"{filename}.encrypted"
                        
                        with open(output_path, 'wb') as f:
                            f.write(encrypted_content)
                        
                        print(f"\n✅ Archivo guardado (cifrado): {output_path}")
                        print(f"📦 Tamaño: {len(encrypted_content)} bytes")

            except Exception as e:
                print(f"❌ Error guardando archivo: {e}")
                if self.debug:
                    import traceback
                    traceback.print_exc()
        elif response:
            print(f"\n❌ Error: {response.get('error')}")

    def delete_file(self):
        """Eliminar archivo del servidor"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return

        print("\n🗑️  ELIMINAR ARCHIVO\n")
        file_id = input("ID del archivo: ").strip()

        if not file_id:
            print("❌ ID inválido")
            return

        confirm = input(f"¿Está seguro de eliminar el archivo {file_id}? (s/N): ").strip().lower()

        if confirm != 's':
            print("❌ Operación cancelada")
            return

        response = self.make_request('DELETE', f'/api/files/{file_id}')

        if response and response.get('message'):
            print(f"\n✅ {response['message']}")
        elif response:
            print(f"\n❌ Error: {response.get('error')}")

    def get_file_access_log(self):
        """Obtener log de accesos de un archivo"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return

        print("\n📜 LOG DE ACCESOS\n")
        file_id = input("ID del archivo: ").strip()

        if not file_id:
            print("❌ ID inválido")
            return

        response = self.make_request('GET', f'/api/files/{file_id}/access-log')

        if response and response.get('access_log'):
            logs = response['access_log']
            print(f"\nArchivo: {response.get('filename')}")
            print(f"Total de accesos: {len(logs)}\n")

            for log in logs:
                print(f"🕒 {log.get('timestamp')}")
                print(f"   Usuario: {log.get('user_name')} ({log.get('user_email')})")
                print(f"   Acción: {log.get('action')}")
                print(f"   IP: {log.get('ip_address', 'N/A')}")
                print()
        elif response:
            print(f"\n❌ Error: {response.get('error')}")

    def verify_file_integrity(self):
        """Verificar integridad de un archivo"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return

        print("\n🔍 VERIFICAR INTEGRIDAD\n")
        file_id = input("ID del archivo: ").strip()

        if not file_id:
            print("❌ ID inválido")
            return

        response = self.make_request('POST', f'/api/files/verify-integrity/{file_id}')

        if response and not response.get('error'):
            print(f"\n📄 Archivo: {response.get('filename')}")
            print(f"🔒 Estado: {response.get('status')}")

            if response.get('integrity_valid'):
                print("✅ Integridad verificada correctamente")
            else:
                print("⚠️  ADVERTENCIA: La integridad del archivo puede estar comprometida")

            print(f"\nHash original: {response.get('original_hash')}")
            print(f"Hash actual: {response.get('current_hash')}")
            print(f"Última verificación: {response.get('last_verified')}")
        elif response:
            print(f"\n❌ Error: {response.get('error')}")
    
    def health_check(self):
        """Verificar estado del servidor"""
        print("\n💓 Verificando estado del servidor...\n")
        response = self.make_request('GET', '/health')
        
        if response:
            print(f"Estado: {response.get('status')}")
            print(f"Base de datos: {response.get('database')}")
    
    def list_users(self):
        """Listar usuarios del sistema (solo administradores)"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return
        
        print("\n👥 USUARIOS DEL SISTEMA\n")
        response = self.make_request('GET', '/api/auth/users')
        
        if response and response.get('error'):
            if 'admin' in response.get('error', '').lower():
                print("❌ Solo los administradores pueden ver la lista de usuarios")
            else:
                print(f"❌ Error: {response.get('error')}")
        elif response and response.get('users'):
            users = response['users']
            print(f"Total de usuarios: {len(users)}\n")
            
            for u in users:
                status = "✅ Activo" if u.get('is_active') else "❌ Inactivo"
                admin = "👑 Admin" if u.get('is_admin') else "👤 Usuario"
                print(f"{admin} - {status}")
                print(f"   ID: {u.get('id')}")
                print(f"   Nombre: {u.get('nombre')} {u.get('apellidos')}")
                print(f"   Email: {u.get('email')}")
                print(f"   Nivel: {u.get('clearance_level')}")
                print()
        else:
            print("No hay usuarios")
    
    def activate_user(self):
        """Activar usuario (solo administradores)"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return
        
        print("\n✅ ACTIVAR USUARIO\n")
        user_id = input("ID del usuario a activar: ").strip()
        
        if not user_id.isdigit():
            print("❌ ID inválido")
            return
        
        response = self.make_request('POST', f'/api/auth/users/{user_id}/activate')
        
        if response and response.get('error'):
            if 'admin' in response.get('error', '').lower():
                print("❌ Solo los administradores pueden activar usuarios")
            else:
                print(f"❌ Error: {response.get('error')}")
        elif response and response.get('message'):
            print(f"✅ {response['message']}")
    
    def share_file(self):
        """Compartir archivo con otro usuario"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return
        
        print("\n🔗 COMPARTIR ARCHIVO\n")
        
        # Solicitar ID del archivo
        file_id = input("ID del archivo a compartir: ").strip()
        if not file_id.isdigit():
            print("❌ ID inválido")
            return
        
        # Solicitar email del destinatario
        recipient_email = input("Email del destinatario: ").strip()
        if not recipient_email or '@' not in recipient_email:
            print("❌ Email inválido")
            return
        
        # Solicitar permisos
        print("\n📋 Permisos:")
        can_download = input("¿Permitir descarga? (s/N): ").strip().lower() == 's'
        can_share = input("¿Permitir re-compartir? (s/N): ").strip().lower() == 's'
        
        # Solicitar expiración (opcional)
        expires_at = None
        expires_input = input("Días hasta expiración (Enter para sin expiración): ").strip()
        if expires_input.isdigit():
            from datetime import datetime, timedelta
            expires_at = (datetime.utcnow() + timedelta(days=int(expires_input))).isoformat() + 'Z'
        
        # Solicitar contraseña para descifrar clave privada
        password = getpass.getpass("Contraseña para descifrar clave privada: ")
        
        if not password:
            print("❌ Contraseña requerida")
            return
        
        print("\n🔄 Re-cifrando clave AES para el destinatario...")
        
        # Primero necesitamos obtener el archivo y la clave pública del destinatario
        # Descargar el archivo para obtener la clave AES cifrada
        file_response = self.make_request('POST', f'/api/files/{file_id}/download')
        if not file_response or file_response.get('error'):
            print(f"❌ Error obteniendo archivo: {file_response.get('error') if file_response else 'Sin respuesta'}")
            return
        
        download_data = file_response.get('download_data')
        if not download_data:
            print("❌ Error: no se obtuvieron datos del archivo")
            return
        
        encrypted_aes_key = download_data['encrypted_aes_key']
        
        # Obtener clave pública del destinatario usando el nuevo endpoint
        recipient_response = self.make_request('POST', '/api/auth/user/public-key', data={'email': recipient_email})
        if not recipient_response or recipient_response.get('error'):
            print(f"❌ Error obteniendo clave pública: {recipient_response.get('error') if recipient_response else 'Sin respuesta'}")
            return
        
        recipient_public_key = recipient_response['public_key']
        
        # Obtener el perfil del usuario actual para obtener su clave privada cifrada
        profile_response = self.make_request('GET', '/api/auth/profile')
        if not profile_response or profile_response.get('error'):
            print(f"❌ Error obteniendo perfil: {profile_response.get('error') if profile_response else 'Sin respuesta'}")
            return
        
        # El endpoint retorna {'user': {...}}
        user_data = profile_response.get('user')
        if not user_data:
            print("❌ Error: no se obtuvo información del usuario")
            return
        
        encrypted_private_key = user_data.get('encrypted_private_key')
        key_derivation_params = user_data.get('key_derivation_params')
        
        if not encrypted_private_key or not key_derivation_params:
            print("❌ Error: usuario no tiene clave privada cifrada. Debe registrarse nuevamente.")
            return
        
        if self.debug:
            print(f"[DEBUG] encrypted_private_key length: {len(encrypted_private_key) if encrypted_private_key else 0}")
            print(f"[DEBUG] key_derivation_params: {key_derivation_params[:100] if key_derivation_params else 'None'}...")
        
        try:
            # Descifrar la clave privada del usuario actual
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.backends import default_backend
            
            if self.debug:
                print("[DEBUG] Paso 1: Derivando clave desde contraseña...")
            
            # Derivar clave de cifrado desde la contraseña
            import json
            params = json.loads(key_derivation_params)
            salt = base64.b64decode(params['salt'])
            iterations = params['iterations']
            
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            if self.debug:
                print("[DEBUG] Paso 2: Descifrando clave privada...")
            
            # Descifrar la clave privada
            from cryptography.fernet import Fernet, InvalidToken
            fernet = Fernet(key)
            try:
                private_key_pem = fernet.decrypt(encrypted_private_key.encode())
            except InvalidToken:
                print("❌ Error: Contraseña incorrecta o clave privada corrupta")
                print("   Por favor, verifique que está usando el mismo password con el que se registró")
                return
            
            if self.debug:
                print("[DEBUG] Paso 3: Cargando clave privada...")
            
            # Cargar la clave privada
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            if self.debug:
                print("[DEBUG] Paso 4: Descifrando clave AES del archivo...")
            
            # Descifrar la clave AES con la clave privada del usuario actual
            encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key)
            aes_key = private_key.decrypt(
                encrypted_aes_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            if self.debug:
                print(f"[DEBUG] Paso 5: Clave AES descifrada, longitud: {len(aes_key)}")
                print("[DEBUG] Paso 6: Cargando clave pública del destinatario...")
            
            # Cargar la clave pública del destinatario
            recipient_public_key_obj = serialization.load_pem_public_key(
                recipient_public_key.encode(),
                backend=default_backend()
            )
            
            if self.debug:
                print("[DEBUG] Paso 7: Re-cifrando clave AES para destinatario...")
            
            # Re-cifrar la clave AES con la clave pública del destinatario
            encrypted_aes_key_for_recipient = recipient_public_key_obj.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            if self.debug:
                print("[DEBUG] Paso 8: Codificando a base64...")
            
            encrypted_aes_key_for_recipient_b64 = base64.b64encode(
                encrypted_aes_key_for_recipient
            ).decode('utf-8')
            
            if self.debug:
                print(f"[DEBUG] ✅ Re-cifrado completo, longitud: {len(encrypted_aes_key_for_recipient_b64)}")
            
        except Exception as e:
            print(f"❌ Error re-cifrando clave AES: {str(e)}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return
        
        # Enviar solicitud de compartir
        share_data = {
            'recipient_email': recipient_email,
            'password': password,
            'encrypted_aes_key_for_recipient': encrypted_aes_key_for_recipient_b64,
            'can_download': can_download,
            'can_share': can_share
        }
        
        if expires_at:
            share_data['expires_at'] = expires_at
        
        response = self.make_request('POST', f'/api/files/{file_id}/share', data=share_data)
        
        if response and response.get('message'):
            print(f"\n✅ {response['message']}")
            print(f"Compartido con: {response.get('shared_with')}")
            print(f"Puede descargar: {'Sí' if response.get('can_download') else 'No'}")
            print(f"Puede re-compartir: {'Sí' if response.get('can_share') else 'No'}")
            if response.get('expires_at'):
                print(f"Expira: {response.get('expires_at')}")
        elif response:
            print(f"❌ Error: {response.get('error')}")
    
    def list_shared_files(self):
        """Listar archivos compartidos conmigo"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return
        
        print("\n📨 ARCHIVOS COMPARTIDOS CONMIGO\n")
        response = self.make_request('GET', '/api/files/shared-with-me')
        
        if response and response.get('shared_files'):
            files = response['shared_files']
            if not files:
                print("No hay archivos compartidos")
                return
            
            print(f"Total: {len(files)} archivo(s)\n")
            
            for file in files:
                print(f"{'='*60}")
                print(f"Share ID: {file['share_id']}")
                print(f"Archivo ID: {file['file_id']}")
                print(f"Título: {file['title']}")
                print(f"Nombre: {file['filename']}")
                print(f"Tamaño: {file['file_size']:,} bytes")
                print(f"Tipo: {file['mime_type']}")
                print(f"Clasificación: {file['classification_level']}")
                print(f"Compartido por: {file['shared_by']}")
                print(f"Fecha: {file['shared_at']}")
                if file.get('expires_at'):
                    print(f"Expira: {file['expires_at']}")
                print(f"Puede descargar: {'Sí' if file.get('can_download') else 'No'}")
                print(f"Puede re-compartir: {'Sí' if file.get('can_share') else 'No'}")
                print()
        elif response:
            print(f"❌ Error: {response.get('error')}")
    
    def download_shared_file(self):
        """Descargar archivo compartido"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return
        
        print("\n⬇️  DESCARGAR ARCHIVO COMPARTIDO\n")
        
        share_id = input("Share ID del archivo: ").strip()
        if not share_id.isdigit():
            print("❌ Share ID inválido")
            return
        
        # Solicitar código 2FA si está habilitado
        totp_code = None
        profile_response = self.make_request('GET', '/api/auth/profile')
        if profile_response and profile_response.get('is_2fa_enabled'):
            totp_code = input("Código 2FA: ").strip()
        
        # Preparar datos de solicitud
        request_data = {}
        if totp_code:
            request_data['totp_code'] = totp_code
        
        # Descargar archivo compartido
        response = self.make_request('POST', f'/api/files/shared/{share_id}/download', data=request_data)
        
        if not response or response.get('error'):
            print(f"❌ Error: {response.get('error') if response else 'Sin respuesta'}")
            return
        
        download_data = response.get('download_data')
        if not download_data:
            print("❌ Error: no se obtuvieron datos de descarga")
            return
        
        # Solicitar directorio de destino
        output_dir = input("Directorio de destino (Enter para directorio actual): ").strip()
        if not output_dir:
            output_dir = '.'
        
        output_path = Path(output_dir)
        if not output_path.exists():
            print(f"❌ Directorio no existe: {output_dir}")
            return
        
        # Solicitar contraseña para descifrar clave privada
        password = getpass.getpass("Contraseña para descifrar clave privada: ")
        
        if not password:
            print("❌ Contraseña requerida")
            return
        
        try:
            # Obtener clave privada cifrada del perfil
            user_data = profile_response.get('user')
            if not user_data:
                print("❌ Error: no se obtuvo información del usuario")
                return
            
            encrypted_private_key = user_data.get('encrypted_private_key')
            key_derivation_params = user_data.get('key_derivation_params')
            
            if not encrypted_private_key or not key_derivation_params:
                print("❌ Error: usuario no tiene clave privada cifrada. Debe registrarse nuevamente.")
                return
            
            # Descifrar la clave privada
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            import json
            
            # Derivar clave de cifrado desde la contraseña
            params = json.loads(key_derivation_params)
            salt = base64.b64decode(params['salt'])
            iterations = params['iterations']
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Descifrar la clave privada
            fernet = Fernet(key)
            private_key_pem = fernet.decrypt(encrypted_private_key.encode())
            
            # Cargar la clave privada
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            # Descifrar la clave AES (re-cifrada para el destinatario)
            encrypted_aes_key_bytes = base64.b64decode(download_data['encrypted_aes_key'])
            aes_key = private_key.decrypt(
                encrypted_aes_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Descifrar el contenido del archivo
            encrypted_content = base64.b64decode(download_data['encrypted_content'])
            
            # Extraer IV (primeros 16 bytes) y contenido cifrado
            iv = encrypted_content[:16]
            ciphertext = encrypted_content[16:]
            
            # Descifrar con AES
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remover padding PKCS7
            padding_length = padded_data[-1]
            file_content = padded_data[:-padding_length]
            
            # Verificar hash
            import hashlib
            calculated_hash = hashlib.sha256(file_content).hexdigest()
            if calculated_hash != download_data['file_hash']:
                print("⚠️  ADVERTENCIA: Hash del archivo no coincide")
                confirm = input("¿Continuar de todos modos? (s/N): ").strip().lower()
                if confirm != 's':
                    print("❌ Descarga cancelada")
                    return
            
            # Guardar archivo
            filename = download_data['original_filename']
            file_path = output_path / filename
            
            # Si el archivo existe, agregar sufijo
            counter = 1
            while file_path.exists():
                name_parts = filename.rsplit('.', 1)
                if len(name_parts) == 2:
                    file_path = output_path / f"{name_parts[0]}_{counter}.{name_parts[1]}"
                else:
                    file_path = output_path / f"{filename}_{counter}"
                counter += 1
            
            with open(file_path, 'wb') as f:
                f.write(file_content)
            
            print(f"\n✅ Archivo descargado exitosamente")
            print(f"Ubicación: {file_path}")
            print(f"Tamaño: {len(file_content):,} bytes")
            print(f"Hash: {calculated_hash}")
            print(f"Compartido por: {download_data.get('shared_by')}")
            
        except Exception as e:
            print(f"❌ Error descargando archivo: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def list_file_shares(self):
        """Listar shares de un archivo propio"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return
        
        print("\n🔗 SHARES DE ARCHIVO\n")
        
        file_id = input("ID del archivo: ").strip()
        if not file_id.isdigit():
            print("❌ ID inválido")
            return
        
        response = self.make_request('GET', f'/api/files/{file_id}/shares')
        
        if response and response.get('shares'):
            shares = response['shares']
            print(f"\nArchivo: {response.get('filename')}")
            print(f"Total de shares: {len(shares)}\n")
            
            for share in shares:
                print(f"{'='*60}")
                print(f"Share ID: {share['share_id']}")
                print(f"Compartido con: {share['shared_with']}")
                print(f"Fecha: {share['shared_at']}")
                if share.get('expires_at'):
                    print(f"Expira: {share['expires_at']}")
                print(f"Puede descargar: {'Sí' if share.get('can_download') else 'No'}")
                print(f"Puede re-compartir: {'Sí' if share.get('can_share') else 'No'}")
                print()
        elif response:
            print(f"❌ Error: {response.get('error')}")
    
    def revoke_share(self):
        """Revocar acceso compartido"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return
        
        print("\n🚫 REVOCAR ACCESO COMPARTIDO\n")
        
        share_id = input("Share ID a revocar: ").strip()
        if not share_id.isdigit():
            print("❌ Share ID inválido")
            return
        
        confirm = input(f"¿Está seguro de revocar el share {share_id}? (s/N): ").strip().lower()
        if confirm != 's':
            print("❌ Operación cancelada")
            return
        
        response = self.make_request('DELETE', f'/api/files/shared/{share_id}')
        
        if response and response.get('message'):
            print(f"\n✅ {response['message']}")
        elif response:
            print(f"❌ Error: {response.get('error')}")
    
    def deactivate_user(self):
        """Desactivar usuario (solo administradores)"""
        if not self.token:
            print("❌ Debe iniciar sesión primero")
            return
        
        print("\n❌ DESACTIVAR USUARIO\n")
        user_id = input("ID del usuario a desactivar: ").strip()
        
        if not user_id.isdigit():
            print("❌ ID inválido")
            return
        
        response = self.make_request('POST', f'/api/auth/users/{user_id}/deactivate')
        
        if response and response.get('error'):
            if 'admin' in response.get('error', '').lower():
                print("❌ Solo los administradores pueden desactivar usuarios")
            else:
                print(f"❌ Error: {response.get('error')}")
        elif response and response.get('message'):
            print(f"✅ {response['message']}")
            print(f"Seguridad: {response.get('security')}")
        else:
            print("❌ Servidor no disponible")


def print_menu():
    """Mostrar menú principal"""
    print("\n" + "="*60)
    print("🔐 SISTEMA DE PROTECCIÓN DE INFORMACIÓN - CLIENTE CLI")
    print("="*60)
    print("\n📋 MENÚ PRINCIPAL:\n")
    print("  1. Información del servidor")
    print("  2. Verificar estado (health check)")
    print("  3. Registrar nuevo usuario")
    print("  4. Iniciar sesión")
    print("  5. Ver perfil")
    print("  6. Configurar 2FA")
    print("  7. Verificar 2FA")
    print("\n📁 GESTIÓN DE ARCHIVOS (requiere sesión activa):\n")
    print("  8. Subir archivo")
    print("  9. Listar mis archivos")
    print(" 13. Ver información de archivo")
    print(" 14. Descargar archivo")
    print(" 15. Eliminar archivo")
    print(" 16. Ver log de accesos de archivo")
    print(" 17. Verificar integridad de archivo")
    print("\n� COMPARTIR ARCHIVOS (Zero Trust):\n")
    print(" 18. Compartir archivo con usuario")
    print(" 19. Ver archivos compartidos conmigo")
    print(" 20. Descargar archivo compartido")
    print(" 21. Ver shares de mi archivo")
    print(" 22. Revocar acceso compartido")
    print("\n�👑 ADMINISTRACIÓN (requiere permisos):\n")
    print(" 10. Listar usuarios del sistema")
    print(" 11. Activar usuario")
    print(" 12. Desactivar usuario")
    print("\n 99. Cerrar sesión")
    print("  0. Salir")
    print()


def main():
    """Función principal"""
    print("\n🔐 Iniciando cliente de protección de información...")
    
    # Permitir configurar URL del servidor (prioridad: argumento > env > default)
    server_url = None
    if len(sys.argv) > 1 and sys.argv[1].startswith('http'):
        server_url = sys.argv[1]
    
    client = SecureClient(server_url)
    
    print(f"🌐 Conectado a: {client.base_url}")
    
    if client.token:
        print("✅ Sesión activa encontrada")
    else:
        print("⚠️  No hay sesión activa")
    
    while True:
        print_menu()

        try:
            choice = input("Seleccione una opción: ").strip()

            if choice == '1':
                client.server_info()
            elif choice == '2':
                client.health_check()
            elif choice == '3':
                client.register()
            elif choice == '4':
                client.login()
            elif choice == '5':
                client.profile()
            elif choice == '6':
                client.setup_2fa()
            elif choice == '7':
                client.verify_2fa()
            elif choice == '8':
                client.upload_file()
            elif choice == '9':
                client.list_files()
            elif choice == '10':
                client.list_users()
            elif choice == '11':
                client.activate_user()
            elif choice == '12':
                client.deactivate_user()
            elif choice == '13':
                client.get_file_info()
            elif choice == '14':
                client.download_file()
            elif choice == '15':
                client.delete_file()
            elif choice == '16':
                client.get_file_access_log()
            elif choice == '17':
                client.verify_file_integrity()
            elif choice == '18':
                client.share_file()
            elif choice == '19':
                client.list_shared_files()
            elif choice == '20':
                client.download_shared_file()
            elif choice == '21':
                client.list_file_shares()
            elif choice == '22':
                client.revoke_share()
            elif choice == '99':
                client.logout()
            elif choice == '0':
                print("\n👋 ¡Hasta luego!")
                break
            else:
                print("\n❌ Opción inválida")

            input("\nPresione Enter para continuar...")

        except KeyboardInterrupt:
            print("\n\n👋 ¡Hasta luego!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
            input("\nPresione Enter para continuar...")


if __name__ == "__main__":
    main()
