"""
Tests unitarios para los endpoints de archivos (/api/files).
Cubre: list, get, delete, shared-with-me, list-shares.
"""

import pytest
from flask_jwt_extended import create_access_token
from models import SecureFile, UserRole
from tests.conftest import create_test_user, TEST_PUBLIC_KEY_PEM, sign_content_hash


def _make_file(db_session, user):
    """Helper: inserta un SecureFile directamente en la BD."""
    import hashlib, os
    fake_hash = hashlib.sha256(os.urandom(16)).hexdigest()
    f = SecureFile(
        user_id=user.id,
        title='Test File',
        original_filename='test.txt',
        file_size=42,
        mime_type='text/plain',
        classification_level='CONFIDENTIAL',
        encrypted_content=b'fake_enc_content',
        encrypted_aes_key='fake_aes_key==',
        file_hash=fake_hash,
        encrypted_hash=fake_hash,
        digital_signature=sign_content_hash(fake_hash),
    )
    db_session.add(f)
    db_session.flush()
    return f


class TestListFiles:
    """GET /api/files/"""

    def test_list_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.get('/api/files/')
        assert resp.status_code == 401

    def test_list_files_empty(self, app, client, db_session):
        """Lista vacía para usuario sin archivos."""
        user = create_test_user(db_session, email='files_list@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/files/', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'files' in data
        assert data['files'] == []

    def test_list_files_returns_own(self, app, client, db_session):
        """El usuario ve solo sus archivos."""
        user = create_test_user(db_session, email='files_own@test.com',
                                 nombre='Own', apellidos='User')
        db_session.commit()
        _make_file(db_session, user)
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/files/', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        assert len(resp.get_json()['files']) == 1


class TestGetFile:
    """GET /api/files/<id>"""

    def test_get_file_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.get('/api/files/999')
        assert resp.status_code == 401

    def test_get_file_not_found(self, app, client, db_session):
        """Archivo inexistente devuelve 404."""
        user = create_test_user(db_session, email='getfile_nf@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/files/99999', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 404

    def test_get_file_success(self, app, client, db_session):
        """Obtener un archivo propio devuelve 200."""
        user = create_test_user(db_session, email='getfile_ok@test.com',
                                 nombre='Get', apellidos='User')
        db_session.commit()
        f = _make_file(db_session, user)
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get(f'/api/files/{f.id}', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        assert resp.get_json()['file']['id'] == f.id


class TestDeleteFile:
    """DELETE /api/files/<id>"""

    def test_delete_file_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.delete('/api/files/1')
        assert resp.status_code == 401

    def test_delete_file_not_found(self, app, client, db_session):
        """Eliminar archivo inexistente devuelve 404."""
        user = create_test_user(db_session, email='delfile_nf@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.delete('/api/files/99999', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 404

    def test_delete_file_success(self, app, client, db_session):
        """Eliminar un archivo propio devuelve 200."""
        user = create_test_user(db_session, email='delfile_ok@test.com',
                                 nombre='Del', apellidos='User')
        db_session.commit()
        f = _make_file(db_session, user)
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.delete(f'/api/files/{f.id}', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200


class TestSharedWithMe:
    """GET /api/files/shared-with-me"""

    def test_shared_with_me_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.get('/api/files/shared-with-me')
        assert resp.status_code == 401

    def test_shared_with_me_empty(self, app, client, db_session):
        """Lista vacía si no hay archivos compartidos."""
        user = create_test_user(db_session, email='shared_me@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/files/shared-with-me',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'shared_files' in data


class TestFileShares:
    """GET /api/files/<id>/shares"""

    def test_list_file_shares_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.get('/api/files/1/shares')
        assert resp.status_code == 401

    def test_list_file_shares_not_found(self, app, client, db_session):
        """Archivo inexistente devuelve 404."""
        user = create_test_user(db_session, email='shares_nf@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/files/99999/shares',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 404

    def test_list_file_shares_empty(self, app, client, db_session):
        """Archivo sin compartir devuelve lista vacía."""
        user = create_test_user(db_session, email='shares_empty@test.com',
                                 nombre='Shr', apellidos='User')
        db_session.commit()
        f = _make_file(db_session, user)
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get(f'/api/files/{f.id}/shares',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'shares' in data
        assert data['shares'] == []
