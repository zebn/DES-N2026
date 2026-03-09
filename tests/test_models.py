"""
Tests unitarios para modelos de datos (User, Secret, Folder).
"""

import pytest
from datetime import datetime, timedelta
from models import User, UserRole, Secret, SecretType, Folder, generate_uuid
from tests.conftest import create_test_user


class TestUserModel:
    """Tests del modelo User."""

    def test_create_user_defaults(self, db_session):
        """Crear un usuario con valores por defecto."""
        user = create_test_user(db_session)
        assert user.id is not None
        assert user.role == UserRole.USER
        assert user.is_active is True
        assert user.is_2fa_enabled is False
        assert user.failed_login_attempts == 0

    def test_user_set_and_check_password(self, db_session):
        """set_password + check_password deben ser consistentes."""
        user = create_test_user(db_session, password='MySecretPass1!')
        assert user.check_password('MySecretPass1!') is True
        assert user.check_password('WrongPassword') is False

    def test_user_has_role(self, db_session):
        """has_role devuelve True solo para roles que coinciden."""
        admin = create_test_user(db_session, email='admin@test.com', role=UserRole.ADMIN)
        assert admin.has_role('ADMIN') is True
        assert admin.has_role('USER') is False
        assert admin.has_role('ADMIN', 'MANAGER') is True

    def test_user_is_admin_role_property(self, db_session):
        """La propiedad is_admin_role refleja el rol ADMIN."""
        admin = create_test_user(db_session, email='admin2@test.com', role=UserRole.ADMIN)
        normal = create_test_user(db_session, email='normal@test.com', role=UserRole.USER)
        assert admin.is_admin_role is True
        assert normal.is_admin_role is False

    def test_user_is_locked(self, db_session):
        """is_locked devuelve True si locked_until está en el futuro."""
        user = create_test_user(db_session, email='locked@test.com')
        assert user.is_locked() is False

        user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        assert user.is_locked() is True

        user.locked_until = datetime.utcnow() - timedelta(minutes=1)
        assert user.is_locked() is False

    def test_user_to_dict(self, db_session):
        """to_dict retorna los campos esperados."""
        user = create_test_user(db_session, email='dict@test.com')
        d = user.to_dict()
        assert d['email'] == 'dict@test.com'
        assert d['role'] == 'USER'
        assert d['is_admin'] is False
        assert 'password_hash' not in d  # no exponer hash

    def test_user_clearance_legacy(self, db_session):
        """has_clearance (legacy) respeta la jerarquía de niveles."""
        user = create_test_user(db_session, email='clearance@test.com')
        user.clearance_level = 'SECRET'
        assert user.has_clearance('RESTRICTED') is True
        assert user.has_clearance('SECRET') is True
        assert user.has_clearance('TOP_SECRET') is False


class TestSecretModel:
    """Tests del modelo Secret."""

    def test_create_secret(self, db_session):
        """Crear un secreto con campos mínimos."""
        user = create_test_user(db_session, email='secret_owner@test.com')
        secret = Secret(
            owner_id=user.id,
            title='Mi contraseña',
            secret_type=SecretType.PASSWORD,
            encrypted_data='base64encrypteddata==',
            encrypted_aes_key='base64encryptedaeskey==',
            content_hash='a' * 64,
            digital_signature='base64sig==',
        )
        db_session.add(secret)
        db_session.flush()

        assert secret.id is not None
        assert len(secret.id) == 36  # UUID
        assert secret.version == 1
        assert secret.is_deleted is False

    def test_secret_to_dict_hides_encrypted_by_default(self, db_session):
        """to_dict sin include_encrypted no devuelve datos cifrados."""
        user = create_test_user(db_session, email='dict_secret@test.com')
        secret = Secret(
            owner_id=user.id,
            title='API Key',
            secret_type=SecretType.API_KEY,
            encrypted_data='enc_data',
            encrypted_aes_key='enc_key',
            content_hash='b' * 64,
            digital_signature='sig',
        )
        db_session.add(secret)
        db_session.flush()

        d = secret.to_dict(include_encrypted=False)
        assert 'encrypted_data' not in d
        assert d['secret_type'] == 'API_KEY'
        assert d['title'] == 'API Key'

    def test_secret_to_dict_includes_encrypted(self, db_session):
        """to_dict con include_encrypted=True expone datos cifrados."""
        user = create_test_user(db_session, email='enc_secret@test.com')
        secret = Secret(
            owner_id=user.id,
            title='SSH',
            secret_type=SecretType.SSH_KEY,
            encrypted_data='enc_ssh_data',
            encrypted_aes_key='enc_ssh_key',
            content_hash='c' * 64,
            digital_signature='ssh_sig',
        )
        db_session.add(secret)
        db_session.flush()

        d = secret.to_dict(include_encrypted=True)
        assert d['encrypted_data'] == 'enc_ssh_data'
        assert d['encrypted_aes_key'] == 'enc_ssh_key'


class TestFolderModel:
    """Tests del modelo Folder."""

    def test_create_folder(self, db_session):
        """Crear una carpeta raíz."""
        user = create_test_user(db_session, email='folder_owner@test.com')
        folder = Folder(owner_id=user.id, name='Producción')
        db_session.add(folder)
        db_session.flush()

        assert folder.id is not None
        assert folder.parent_id is None
        assert folder.name == 'Producción'

    def test_folder_hierarchy(self, db_session):
        """Crear carpetas con jerarquía padre/hijo."""
        user = create_test_user(db_session, email='hierarchy@test.com')
        parent = Folder(owner_id=user.id, name='Raíz')
        db_session.add(parent)
        db_session.flush()

        child = Folder(owner_id=user.id, name='Sub-carpeta', parent_id=parent.id)
        db_session.add(child)
        db_session.flush()

        assert child.parent_id == parent.id
        assert child.parent.name == 'Raíz'

    def test_folder_to_dict(self, db_session):
        """to_dict devuelve los campos esperados."""
        user = create_test_user(db_session, email='fdict@test.com')
        folder = Folder(owner_id=user.id, name='Test Folder')
        db_session.add(folder)
        db_session.flush()

        d = folder.to_dict()
        assert d['name'] == 'Test Folder'
        assert 'created_at' in d


class TestHelpers:
    """Tests de funciones auxiliares."""

    def test_generate_uuid_format(self):
        """generate_uuid produce UUIDs válidos."""
        uid = generate_uuid()
        assert isinstance(uid, str)
        assert len(uid) == 36
        parts = uid.split('-')
        assert len(parts) == 5

    def test_generate_uuid_uniqueness(self):
        """Cada llamada a generate_uuid devuelve un valor distinto."""
        ids = {generate_uuid() for _ in range(100)}
        assert len(ids) == 100
