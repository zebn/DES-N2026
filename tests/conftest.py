"""
Fixtures compartidos para los tests de SentryVault.
Usa una base de datos SQLite en memoria para aislar cada test.
"""

import os
import pytest

# Forzar entorno de test ANTES de importar la app
os.environ['FLASK_ENV'] = 'development'
os.environ['SECRET_KEY'] = 'test-secret-key-for-unit-tests'
os.environ['JWT_SECRET_KEY'] = 'test-jwt-secret-key-for-unit-tests'

from app import create_app
from models import db as _db, User, UserRole


# ─── RSA keypair real (generada una vez) para que la firma sea verificable ────

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

_TEST_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_TEST_PUBLIC_KEY = _TEST_PRIVATE_KEY.public_key()

TEST_PUBLIC_KEY_PEM = _TEST_PUBLIC_KEY.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

TEST_PRIVATE_KEY_PEM = _TEST_PRIVATE_KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()


def sign_content_hash(content_hash: str) -> str:
    """Firmar un content_hash (string hex) con la clave privada de test.
    Devuelve la firma en base64, igual que crypto_manager.sign_data."""
    signature = _TEST_PRIVATE_KEY.sign(
        content_hash.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


_DUMMY_ENCRYPTED_PRIVATE_KEY = "dummy_encrypted_private_key_base64"
_DUMMY_KEY_DERIVATION_PARAMS = '{"algorithm":"Argon2id","time_cost":3,"memory_cost":65536,"parallelism":4,"salt":"abc123","counter":"0","hash_len":32}'


@pytest.fixture(scope='session')
def app():
    """Crear la aplicación Flask con BD SQLite en memoria."""
    app = create_app('development')
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'JWT_SECRET_KEY': 'test-jwt-secret-key',
        'SERVER_NAME': 'localhost',
    })
    with app.app_context():
        _db.create_all()
    yield app
    with app.app_context():
        _db.drop_all()


@pytest.fixture(autouse=True)
def db_session(app):
    """Proporcionar una transacción limpia por cada test."""
    with app.app_context():
        _db.session.begin_nested()
        yield _db.session
        _db.session.rollback()


@pytest.fixture()
def client(app):
    """Cliente de test de Flask."""
    return app.test_client()


# ─── Helpers ──────────────────────────────────────────────────────────────────


def create_test_user(
    db_session,
    email='test@example.com',
    password='TestPass123!',
    role=UserRole.USER,
    nombre='Test',
    apellidos='User',
):
    """Helper para crear un usuario de test válido con clave RSA real."""
    import secrets as _secrets

    salt = _secrets.token_hex(16)
    user = User(
        nombre=nombre,
        apellidos=apellidos,
        email=email,
        telefono='600000000',
        role=role,
        is_active=True,
        public_key=TEST_PUBLIC_KEY_PEM,
        private_key_encrypted=_DUMMY_ENCRYPTED_PRIVATE_KEY,
        key_derivation_params=_DUMMY_KEY_DERIVATION_PARAMS,
    )
    user.set_password(password, salt)
    db_session.add(user)
    db_session.flush()  # genera user.id sin commit
    return user
