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


class TestLogoutEndpoint:
    """POST /api/auth/logout"""

    def test_logout_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.post('/api/auth/logout')
        assert resp.status_code == 401

    def test_logout_success(self, app, client, db_session):
        """Logout con JWT válido devuelve 200."""
        user = create_test_user(db_session, email='logout@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.post('/api/auth/logout',
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        assert 'Logout' in resp.get_json()['message']


class TestRefreshEndpoint:
    """POST /api/auth/refresh"""

    def test_refresh_requires_refresh_token(self, client):
        """Sin refresh token devuelve 401."""
        resp = client.post('/api/auth/refresh')
        assert resp.status_code == 401

    def test_refresh_with_access_token_fails(self, app, client, db_session):
        """Un access token no sirve en /refresh."""
        user = create_test_user(db_session, email='refresh_acc@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.post('/api/auth/refresh',
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code in (401, 422)  # JWT lib rejects non-refresh tokens

    def test_refresh_success(self, app, client, db_session):
        """Refresh token válido devuelve nuevo access_token."""
        from flask_jwt_extended import create_refresh_token
        user = create_test_user(db_session, email='refresh_ok@test.com')
        db_session.commit()
        with app.app_context():
            refresh_token = create_refresh_token(identity=str(user.id))

        resp = client.post('/api/auth/refresh',
                           headers={'Authorization': f'Bearer {refresh_token}'})
        assert resp.status_code == 200
        assert 'access_token' in resp.get_json()


class TestSetup2FAEndpoint:
    """POST /api/auth/setup-2fa"""

    def test_setup_2fa_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.post('/api/auth/setup-2fa')
        assert resp.status_code == 401

    def test_setup_2fa_returns_qr(self, app, client, db_session):
        """Usuario sin 2FA activo recibe secreto y QR."""
        user = create_test_user(db_session, email='setup2fa@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.post('/api/auth/setup-2fa',
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'secret' in data
        assert 'qr_code' in data


class TestListUsersEndpoint:
    """GET /api/auth/users"""

    def test_list_users_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.get('/api/auth/users')
        assert resp.status_code == 401

    def test_list_users_forbidden_for_user(self, app, client, db_session):
        """Un USER normal recibe 403."""
        user = create_test_user(db_session, email='listusers_u@test.com', role=UserRole.USER)
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/auth/users', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 403

    def test_list_users_admin_ok(self, app, client, db_session):
        """ADMIN recibe lista de usuarios."""
        admin = create_test_user(db_session, email='listusers_a@test.com', role=UserRole.ADMIN)
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(admin.id))

        resp = client.get('/api/auth/users', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        assert 'users' in resp.get_json()


class TestActivateDeactivateEndpoint:
    """POST /api/auth/users/<id>/activate  &  deactivate"""

    def test_activate_requires_admin(self, app, client, db_session):
        """Un USER no puede activar a otros."""
        user = create_test_user(db_session, email='activ_u@test.com', role=UserRole.USER)
        target = create_test_user(db_session, email='activ_t@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.post(f'/api/auth/users/{target.id}/activate',
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 403

    def test_admin_can_activate(self, app, client, db_session):
        """ADMIN puede activar un usuario inactivo."""
        admin = create_test_user(db_session, email='activ_a@test.com', role=UserRole.ADMIN)
        target = create_test_user(db_session, email='activ_tgt@test.com')
        target.is_active = False
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(admin.id))

        resp = client.post(f'/api/auth/users/{target.id}/activate',
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200

    def test_deactivate_requires_admin(self, app, client, db_session):
        """Un USER no puede desactivar a otros."""
        user = create_test_user(db_session, email='deact_u@test.com', role=UserRole.USER)
        target = create_test_user(db_session, email='deact_t@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.post(f'/api/auth/users/{target.id}/deactivate',
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 403

    def test_admin_can_deactivate_other(self, app, client, db_session):
        """ADMIN puede desactivar a otro usuario."""
        admin = create_test_user(db_session, email='deact_a@test.com', role=UserRole.ADMIN)
        target = create_test_user(db_session, email='deact_tgt@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(admin.id))

        resp = client.post(f'/api/auth/users/{target.id}/deactivate',
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200


class TestPublicKeyEndpoint:
    """POST /api/auth/user/public-key"""

    def test_public_key_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.post('/api/auth/user/public-key', json={'email': 'x@y.com'})
        assert resp.status_code == 401

    def test_public_key_not_found(self, app, client, db_session):
        """Email inexistente devuelve 404."""
        user = create_test_user(db_session, email='pk_caller@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.post('/api/auth/user/public-key',
                           json={'email': 'nobody@nowhere.com'},
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 404

    def test_public_key_success(self, app, client, db_session):
        """Devuelve la clave pública del usuario buscado."""
        caller = create_test_user(db_session, email='pk_caller2@test.com')
        target = create_test_user(db_session, email='pk_target@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(caller.id))

        resp = client.post('/api/auth/user/public-key',
                           json={'email': 'pk_target@test.com'},
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['email'] == 'pk_target@test.com'
        assert 'public_key' in data
