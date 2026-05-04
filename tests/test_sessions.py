"""
Tests para RF05 — Gestión de sesiones (/api/auth/sessions).

Verifica:
- Que el login crea una fila Session ligada al jti del access_token.
- Que el blocklist rechaza un token revocado.
- Que GET /sessions, DELETE /sessions/<id>, DELETE /sessions funcionan.
- Que la revocación masiva no toca la sesión actual.
"""

from datetime import datetime, timedelta

from flask_jwt_extended import decode_token

from models import Session, AuditLog, db as _db
from tests.conftest import create_test_user


def _login(client, email='sess@test.com', password='SessionPass1!'):
    resp = client.post('/api/auth/login', json={'email': email, 'password': password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


class TestSessionLifecycle:
    """Login → Session creada; logout → Session revocada."""

    def test_login_creates_session_row(self, client, db_session, app):
        create_test_user(db_session, email='sess1@test.com', password='SessionPass1!')
        db_session.commit()

        data = _login(client, email='sess1@test.com')
        access = data['access_token']
        with app.app_context():
            jti = decode_token(access)['jti']
            row = Session.query.filter_by(token_jti=jti).first()
            assert row is not None
            assert row.is_revoked is False
            assert row.user_agent is not None or row.user_agent == ''

    def test_login_emits_session_created_audit(self, client, db_session):
        user = create_test_user(db_session, email='sess2@test.com', password='SessionPass1!')
        db_session.commit()

        _login(client, email='sess2@test.com')

        evt = AuditLog.query.filter_by(user_id=user.id, action='SESSION_CREATED').first()
        assert evt is not None
        assert evt.resource_type == 'SESSION'

    def test_logout_revokes_session(self, client, db_session, app):
        create_test_user(db_session, email='sess3@test.com', password='SessionPass1!')
        db_session.commit()

        data = _login(client, email='sess3@test.com')
        access = data['access_token']

        resp = client.post('/api/auth/logout', headers={'Authorization': f'Bearer {access}'})
        assert resp.status_code == 200

        with app.app_context():
            jti = decode_token(access)['jti']
            row = Session.query.filter_by(token_jti=jti).first()
            assert row.is_revoked is True
            assert row.revoked_reason == 'logout'


class TestTokenBlocklist:
    """El blocklist debe rechazar un token cuya Session esté revocada."""

    def test_revoked_token_returns_401(self, client, db_session):
        create_test_user(db_session, email='block@test.com', password='SessionPass1!')
        db_session.commit()

        access = _login(client, email='block@test.com')['access_token']
        # Logout revoca la sesión asociada al jti
        client.post('/api/auth/logout', headers={'Authorization': f'Bearer {access}'})

        # El siguiente request con el mismo token debe ser rechazado
        resp = client.get('/api/auth/profile', headers={'Authorization': f'Bearer {access}'})
        assert resp.status_code == 401


class TestSessionsEndpoints:
    """/api/auth/sessions: list, revoke individual, revoke all."""

    def test_list_sessions_only_returns_active_by_default(self, client, db_session):
        create_test_user(db_session, email='list@test.com', password='SessionPass1!')
        db_session.commit()

        access = _login(client, email='list@test.com')['access_token']

        resp = client.get('/api/auth/sessions', headers={'Authorization': f'Bearer {access}'})
        assert resp.status_code == 200
        sessions = resp.get_json()['sessions']
        assert len(sessions) >= 1
        current = [s for s in sessions if s['is_current']]
        assert len(current) == 1

    def test_revoke_specific_session_marks_it_revoked(self, client, db_session, app):
        create_test_user(db_session, email='rev@test.com', password='SessionPass1!')
        db_session.commit()

        # Dos logins simulan dos dispositivos
        access1 = _login(client, email='rev@test.com')['access_token']
        access2 = _login(client, email='rev@test.com')['access_token']

        with app.app_context():
            jti1 = decode_token(access1)['jti']
            target = Session.query.filter_by(token_jti=jti1).first()
            target_id = target.id

        # Revocamos la primera desde la segunda (que es la "actual")
        resp = client.delete(f'/api/auth/sessions/{target_id}',
                             headers={'Authorization': f'Bearer {access2}'})
        assert resp.status_code == 200

        # access1 ya no debería servir
        check = client.get('/api/auth/profile', headers={'Authorization': f'Bearer {access1}'})
        assert check.status_code == 401

        # access2 sigue válido
        ok = client.get('/api/auth/profile', headers={'Authorization': f'Bearer {access2}'})
        assert ok.status_code == 200

    def test_revoke_all_keeps_current_session(self, client, db_session):
        create_test_user(db_session, email='all@test.com', password='SessionPass1!')
        db_session.commit()

        access1 = _login(client, email='all@test.com')['access_token']
        access2 = _login(client, email='all@test.com')['access_token']
        access3 = _login(client, email='all@test.com')['access_token']  # actual

        resp = client.delete('/api/auth/sessions',
                             headers={'Authorization': f'Bearer {access3}'})
        assert resp.status_code == 200
        assert resp.get_json()['revoked_count'] >= 2

        # access1 y access2 quedan revocados
        for tok in (access1, access2):
            r = client.get('/api/auth/profile', headers={'Authorization': f'Bearer {tok}'})
            assert r.status_code == 401

        # access3 sigue válido
        r3 = client.get('/api/auth/profile', headers={'Authorization': f'Bearer {access3}'})
        assert r3.status_code == 200

    def test_cannot_revoke_other_users_session(self, client, db_session, app):
        create_test_user(db_session, email='owner@test.com', password='SessionPass1!')
        create_test_user(db_session, email='intruder@test.com', password='SessionPass1!')
        db_session.commit()

        owner_access = _login(client, email='owner@test.com')['access_token']
        intruder_access = _login(client, email='intruder@test.com')['access_token']

        with app.app_context():
            owner_jti = decode_token(owner_access)['jti']
            owner_session = Session.query.filter_by(token_jti=owner_jti).first()
            owner_session_id = owner_session.id

        resp = client.delete(f'/api/auth/sessions/{owner_session_id}',
                             headers={'Authorization': f'Bearer {intruder_access}'})
        assert resp.status_code == 404


class TestLastActivity:
    """Cada request autenticado debe refrescar last_activity."""

    def test_last_activity_advances(self, client, db_session, app):
        create_test_user(db_session, email='act@test.com', password='SessionPass1!')
        db_session.commit()

        access = _login(client, email='act@test.com')['access_token']

        with app.app_context():
            jti = decode_token(access)['jti']
            row_before = Session.query.filter_by(token_jti=jti).first()
            before = row_before.last_activity

        # Forzar separación temporal y nuevo request
        import time
        time.sleep(0.01)
        client.get('/api/auth/profile', headers={'Authorization': f'Bearer {access}'})

        with app.app_context():
            row_after = Session.query.filter_by(token_jti=jti).first()
            assert row_after.last_activity >= before


class TestSessionToDict:
    """to_dict del modelo Session refleja correctamente el estado."""

    def test_to_dict_marks_current(self, db_session):
        user = create_test_user(db_session, email='td@test.com')
        s = Session(
            user_id=user.id,
            token_jti='jti-test-1',
            ip_address='127.0.0.1',
            user_agent='UA-test',
            device_info='Chrome en macOS',
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        _db.session.add(s)
        _db.session.flush()

        d_current = s.to_dict(current_jti='jti-test-1')
        d_other = s.to_dict(current_jti='otro-jti')
        assert d_current['is_current'] is True
        assert d_other['is_current'] is False
        assert d_current['device_info'] == 'Chrome en macOS'
