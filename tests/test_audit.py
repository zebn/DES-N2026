"""
Tests unitarios para los endpoints de auditoría (/api/audit).
Cubre: logs, logs/user, logs/secret, logs/me, stats, export.
"""

import pytest
from flask_jwt_extended import create_access_token
from models import AuditLog, Secret, SecretType, UserRole
from tests.conftest import create_test_user, sign_content_hash


def _make_audit_log(db_session, user_id, action='LOGIN_SUCCESS'):
    """Helper: inserta un AuditLog directamente en la BD."""
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type='USER',
        resource_id=user_id,
        success=True,
    )
    db_session.add(log)
    db_session.flush()
    return log


def _make_secret(db_session, user, app, client, token):
    """Helper: crea un secreto vía API y devuelve su id."""
    ch = 'a1b2c3' * 10 + 'ab'
    resp = client.post('/api/secrets', json={
        'title': 'Audit Secret',
        'secret_type': 'NOTE',
        'encrypted_data': 'enc',
        'encrypted_aes_key': 'key',
        'content_hash': ch,
        'digital_signature': sign_content_hash(ch),
    }, headers={'Authorization': f'Bearer {token}'})
    return resp.get_json()['secret']['id']


class TestGlobalLogs:
    """GET /api/audit/logs — solo ADMIN/AUDITOR"""

    def test_logs_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.get('/api/audit/logs')
        assert resp.status_code == 401

    def test_logs_forbidden_for_user(self, app, client, db_session):
        """Un USER normal recibe 403."""
        user = create_test_user(db_session, email='audit_user@test.com', role=UserRole.USER)
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/audit/logs', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 403

    def test_logs_accessible_for_admin(self, app, client, db_session):
        """ADMIN puede ver logs globales."""
        admin = create_test_user(db_session, email='audit_admin@test.com', role=UserRole.ADMIN)
        db_session.commit()
        _make_audit_log(db_session, admin.id)
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(admin.id))

        resp = client.get('/api/audit/logs', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'logs' in data
        assert 'total' in data

    def test_logs_accessible_for_auditor(self, app, client, db_session):
        """AUDITOR puede ver logs globales."""
        auditor = create_test_user(db_session, email='auditor@test.com', role=UserRole.AUDITOR)
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(auditor.id))

        resp = client.get('/api/audit/logs', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200


class TestUserLogs:
    """GET /api/audit/logs/user/<id>"""

    def test_user_logs_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.get('/api/audit/logs/user/1')
        assert resp.status_code == 401

    def test_user_logs_own(self, app, client, db_session):
        """Un usuario puede ver sus propios logs."""
        user = create_test_user(db_session, email='userlog_own@test.com')
        db_session.commit()
        _make_audit_log(db_session, user.id)
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get(f'/api/audit/logs/user/{user.id}',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['total'] >= 1

    def test_user_logs_other_forbidden(self, app, client, db_session):
        """Un USER no puede ver logs de otro usuario."""
        user = create_test_user(db_session, email='userlog_u@test.com')
        other = create_test_user(db_session, email='userlog_other@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get(f'/api/audit/logs/user/{other.id}',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 403


class TestSecretLogs:
    """GET /api/audit/logs/secret/<id>"""

    def test_secret_logs_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.get('/api/audit/logs/secret/some-id')
        assert resp.status_code == 401

    def test_secret_logs_not_found(self, app, client, db_session):
        """Secreto inexistente devuelve 404."""
        user = create_test_user(db_session, email='seclog_nf@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/audit/logs/secret/nonexistent-id',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 404

    def test_secret_logs_owner_can_read(self, app, client, db_session):
        """El propietario del secreto puede ver sus logs."""
        user = create_test_user(db_session, email='seclog_owner@test.com')
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))
        secret_id = _make_secret(db_session, user, app, client, token)

        resp = client.get(f'/api/audit/logs/secret/{secret_id}',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        assert 'logs' in resp.get_json()


class TestMyLogs:
    """GET /api/audit/logs/me"""

    def test_my_logs_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.get('/api/audit/logs/me')
        assert resp.status_code == 401

    def test_my_logs_returns_own(self, app, client, db_session):
        """Devuelve solo logs del usuario autenticado."""
        user = create_test_user(db_session, email='mylogs@test.com')
        db_session.commit()
        _make_audit_log(db_session, user.id, action='LOGIN_SUCCESS')
        db_session.commit()

        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/audit/logs/me', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'logs' in data
        assert data['total'] >= 1


class TestAuditStats:
    """GET /api/audit/stats — solo ADMIN/AUDITOR"""

    def test_stats_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.get('/api/audit/stats')
        assert resp.status_code == 401

    def test_stats_forbidden_for_user(self, app, client, db_session):
        """Un USER normal recibe 403."""
        user = create_test_user(db_session, email='stats_user@test.com', role=UserRole.USER)
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.get('/api/audit/stats', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 403

    def test_stats_admin_ok(self, app, client, db_session):
        """ADMIN recibe estadísticas."""
        admin = create_test_user(db_session, email='stats_admin@test.com', role=UserRole.ADMIN)
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(admin.id))

        resp = client.get('/api/audit/stats', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'total_events' in data
        assert 'success_rate' in data


class TestAuditExport:
    """POST /api/audit/export — solo ADMIN/AUDITOR"""

    def test_export_requires_auth(self, client):
        """Sin JWT devuelve 401."""
        resp = client.post('/api/audit/export', json={})
        assert resp.status_code == 401

    def test_export_forbidden_for_user(self, app, client, db_session):
        """Un USER normal recibe 403."""
        user = create_test_user(db_session, email='export_user@test.com', role=UserRole.USER)
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.post('/api/audit/export', json={},
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 403

    def test_export_admin_ok(self, app, client, db_session):
        """ADMIN puede exportar logs."""
        admin = create_test_user(db_session, email='export_admin@test.com', role=UserRole.ADMIN)
        db_session.commit()
        with app.app_context():
            token = create_access_token(identity=str(admin.id))

        resp = client.post('/api/audit/export', json={},
                           headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
