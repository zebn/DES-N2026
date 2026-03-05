"""
Tests unitarios para los endpoints de autenticación (/api/auth).
"""

import json
import pytest
from flask_jwt_extended import create_access_token
from models import User, UserRole, AuditLog
from tests.conftest import create_test_user


class TestRegisterEndpoint:
    """POST /api/auth/register"""

    def test_register_missing_fields(self, client):
        """Registro sin campos obligatorios devuelve 400."""
        resp = client.post('/api/auth/register', json={'email': 'x@y.com'})
        assert resp.status_code == 400

    def test_register_success(self, client, db_session):
        """Registro con todos los campos devuelve 201."""
        payload = {
            'nombre': 'Ana',
            'apellidos': 'García López',
            'email': 'ana@example.com',
            'password': 'SuperSecure1!',
            'public_key': '-----BEGIN PUBLIC KEY-----\nMIIBIjANtest\n-----END PUBLIC KEY-----',
            'encrypted_private_key': 'enc_priv_key_base64',
            'key_derivation_params': json.dumps({
                'algorithm': 'Argon2id',
                'time_cost': 3,
                'memory_cost': 65536,
                'parallelism': 4,
                'salt': 'aabbcc',
                'counter': '0',
                'hash_len': 32,
            }),
        }
        resp = client.post('/api/auth/register', json=payload)
        assert resp.status_code == 201
        data = resp.get_json()
        assert 'user_id' in data

    def test_register_duplicate_email(self, client, db_session):
        """Registro con email duplicado devuelve error."""
        payload = {
            'nombre': 'A',
            'apellidos': 'B',
            'email': 'dup@example.com',
            'password': 'Pass1234!',
            'public_key': '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
            'encrypted_private_key': 'x',
            'key_derivation_params': '{}',
        }
        resp1 = client.post('/api/auth/register', json=payload)
        assert resp1.status_code == 201

        resp2 = client.post('/api/auth/register', json=payload)
        assert resp2.status_code in (400, 409)


class TestLoginEndpoint:
    """POST /api/auth/login"""

    def test_login_wrong_password(self, client, db_session):
        """Login con contraseña incorrecta devuelve 401."""
        create_test_user(db_session, email='logintest@test.com', password='CorrectPass1!')
        db_session.commit()

        resp = client.post('/api/auth/login', json={
            'email': 'logintest@test.com',
            'password': 'WrongPassword',
        })
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client):
        """Login con email inexistente devuelve 401."""
        resp = client.post('/api/auth/login', json={
            'email': 'noexiste@test.com',
            'password': 'AnyPass1!',
        })
        assert resp.status_code == 401

    def test_login_success(self, client, db_session):
        """Login correcto devuelve access_token."""
        create_test_user(db_session, email='good@test.com', password='GoodPass1!')
        db_session.commit()

        resp = client.post('/api/auth/login', json={
            'email': 'good@test.com',
            'password': 'GoodPass1!',
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'access_token' in data


class TestProfileEndpoint:
    """GET /api/auth/profile"""

    def test_profile_no_token(self, client):
        """Acceder al perfil sin JWT devuelve 401."""
        resp = client.get('/api/auth/profile')
        assert resp.status_code == 401

    def test_profile_with_token(self, app, client, db_session):
        """Acceder al perfil con JWT válido devuelve datos del usuario."""
        user = create_test_user(db_session, email='profile@test.com')
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/auth/profile', headers={
            'Authorization': f'Bearer {token}',
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['user']['email'] == 'profile@test.com'


class TestRolesEndpoint:
    """GET /api/auth/roles  &  PUT /api/auth/users/:id/role"""

    def test_list_roles(self, app, client, db_session):
        """Listar roles disponibles."""
        user = create_test_user(db_session, email='roles@test.com')
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/auth/roles', headers={
            'Authorization': f'Bearer {token}',
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'roles' in data

    def test_change_role_requires_admin(self, app, client, db_session):
        """Cambiar rol de otro usuario requiere rol ADMIN."""
        normal = create_test_user(db_session, email='noroles@test.com', role=UserRole.USER)
        target = create_test_user(db_session, email='target@test.com', role=UserRole.USER)
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(normal.id))

        resp = client.put(
            f'/api/auth/users/{target.id}/role',
            json={'role': 'MANAGER'},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert resp.status_code == 403

    def test_change_role_as_admin(self, app, client, db_session):
        """ADMIN puede cambiar el rol de otros usuarios."""
        admin = create_test_user(db_session, email='admrole@test.com', role=UserRole.ADMIN)
        target = create_test_user(db_session, email='trgt@test.com', role=UserRole.USER)
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(admin.id))

        resp = client.put(
            f'/api/auth/users/{target.id}/role',
            json={'role': 'MANAGER'},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert resp.status_code == 200
