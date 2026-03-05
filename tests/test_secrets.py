"""
Tests unitarios para los endpoints CRUD de secretos (/api/secrets).
"""

import json
import pytest
from flask_jwt_extended import create_access_token
from models import Secret, SecretType, Folder
from tests.conftest import create_test_user, sign_content_hash


class TestSecretsCreate:
    """POST /api/secrets"""

    def test_create_secret_no_auth(self, client):
        """Crear secreto sin JWT devuelve 401."""
        resp = client.post('/api/secrets', json={'title': 'x'})
        assert resp.status_code == 401

    def test_create_secret_missing_fields(self, app, client, db_session):
        """Crear secreto sin campos obligatorios devuelve 400."""
        user = create_test_user(db_session, email='sec_create@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))
        resp = client.post('/api/secrets', json={'title': 'solo titulo'}, headers={
            'Authorization': f'Bearer {token}',
        })
        assert resp.status_code == 400

    def test_create_secret_success(self, app, client, db_session):
        """Crear un secreto válido devuelve 201 y el secreto."""
        user = create_test_user(db_session, email='sec_ok@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        content_hash = 'a' * 64
        payload = {
            'title': 'Mi API Key',
            'secret_type': 'API_KEY',
            'encrypted_data': 'base64encdata==',
            'encrypted_aes_key': 'base64aeskey==',
            'content_hash': content_hash,
            'digital_signature': sign_content_hash(content_hash),
        }
        resp = client.post('/api/secrets', json=payload, headers={
            'Authorization': f'Bearer {token}',
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['secret']['secret_type'] == 'API_KEY'
        assert data['secret']['version'] == 1


class TestSecretsList:
    """GET /api/secrets"""

    def test_list_secrets_empty(self, app, client, db_session):
        """Listar secretos sin datos devuelve lista vacía."""
        user = create_test_user(db_session, email='sec_list@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/secrets', headers={
            'Authorization': f'Bearer {token}',
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['total'] == 0
        assert data['secrets'] == []

    def test_list_secrets_returns_own_only(self, app, client, db_session):
        """Cada usuario sólo ve sus propios secretos."""
        user1 = create_test_user(db_session, email='u1@test.com')
        user2 = create_test_user(db_session, email='u2@test.com')
        db_session.commit()

        # Crear secreto para user1
        with app.app_context():
            token1 = create_access_token(identity=str(user1.id))
        ch1 = 'f' * 64
        client.post('/api/secrets', json={
            'title': 'Secreto de u1',
            'secret_type': 'NOTE',
            'encrypted_data': 'x',
            'encrypted_aes_key': 'x',
            'content_hash': ch1,
            'digital_signature': sign_content_hash(ch1),
        }, headers={'Authorization': f'Bearer {token1}'})

        # user2 no debe verlo
        with app.app_context():
            token2 = create_access_token(identity=str(user2.id))
        resp = client.get('/api/secrets', headers={
            'Authorization': f'Bearer {token2}',
        })
        assert resp.get_json()['total'] == 0


class TestSecretsDetail:
    """GET/PUT/DELETE /api/secrets/<id>"""

    def _create_secret(self, app, client, db_session, email='detail@test.com'):
        """Helper: crea un usuario con un secreto y devuelve (token, secret_id)."""
        user = create_test_user(db_session, email=email)
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))
        ch = 'd' * 64
        resp = client.post('/api/secrets', json={
            'title': 'Detail Secret',
            'secret_type': 'PASSWORD',
            'encrypted_data': 'enc',
            'encrypted_aes_key': 'key',
            'content_hash': ch,
            'digital_signature': sign_content_hash(ch),
        }, headers={'Authorization': f'Bearer {token}'})
        return token, resp.get_json()['secret']['id']

    def test_get_secret(self, app, client, db_session):
        """Obtener un secreto existente devuelve 200."""
        token, sid = self._create_secret(app, client, db_session)
        resp = client.get(f'/api/secrets/{sid}', headers={
            'Authorization': f'Bearer {token}',
        })
        assert resp.status_code == 200
        assert resp.get_json()['secret']['id'] == sid

    def test_get_secret_not_found(self, app, client, db_session):
        """Obtener un secreto inexistente devuelve 404."""
        user = create_test_user(db_session, email='nf@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))
        resp = client.get('/api/secrets/nonexistent-uuid', headers={
            'Authorization': f'Bearer {token}',
        })
        assert resp.status_code == 404

    def test_delete_secret_soft(self, app, client, db_session):
        """DELETE marca el secreto como eliminado (soft delete)."""
        token, sid = self._create_secret(app, client, db_session, email='del@test.com')
        resp = client.delete(f'/api/secrets/{sid}', headers={
            'Authorization': f'Bearer {token}',
        })
        assert resp.status_code == 200

        # Después de borrar, GET devuelve 404
        resp2 = client.get(f'/api/secrets/{sid}', headers={
            'Authorization': f'Bearer {token}',
        })
        assert resp2.status_code == 404

    def test_update_secret_creates_version(self, app, client, db_session):
        """PUT crea una nueva versión del secreto."""
        token, sid = self._create_secret(app, client, db_session, email='upd@test.com')
        new_hash = 'e' * 64
        resp = client.put(f'/api/secrets/{sid}', json={
            'encrypted_data': 'new_enc',
            'encrypted_aes_key': 'new_key',
            'content_hash': new_hash,
            'digital_signature': sign_content_hash(new_hash),
            'change_reason': 'rotación',
        }, headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        assert resp.get_json()['version'] == 2


class TestFoldersCrud:
    """POST/GET/PUT/DELETE /api/folders"""

    def test_create_and_list_folders(self, app, client, db_session):
        """Crear y listar carpetas."""
        user = create_test_user(db_session, email='fold@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))
        headers = {'Authorization': f'Bearer {token}'}

        # Crear
        resp = client.post('/api/folders', json={'name': 'Prod'}, headers=headers)
        assert resp.status_code == 201

        # Listar
        resp = client.get('/api/folders', headers=headers)
        assert resp.status_code == 200
        folders = resp.get_json()['folders']
        assert len(folders) == 1
        assert folders[0]['name'] == 'Prod'

    def test_delete_folder(self, app, client, db_session):
        """Eliminar carpeta existente."""
        user = create_test_user(db_session, email='delfold@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))
        headers = {'Authorization': f'Bearer {token}'}

        resp = client.post('/api/folders', json={'name': 'ToDelete'}, headers=headers)
        fid = resp.get_json()['folder']['id']

        resp = client.delete(f'/api/folders/{fid}', headers=headers)
        assert resp.status_code == 200
