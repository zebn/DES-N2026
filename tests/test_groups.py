"""
Tests unitarios para los endpoints de gestión de grupos (/api/groups).
RF03 — Gestión de grupos.
"""

from flask_jwt_extended import create_access_token

from models import Group, GroupMembership, GroupRole, UserRole, AuditLog
from tests.conftest import create_test_user


def _auth(app, user):
    with app.app_context():
        token = create_access_token(identity=str(user.id))
    return {'Authorization': f'Bearer {token}'}


def _create_group(client, headers, name='Equipo A', description=None):
    body = {'name': name}
    if description is not None:
        body['description'] = description
    return client.post('/api/groups', json=body, headers=headers)


class TestCreateGroup:
    """POST /api/groups"""

    def test_create_group_as_manager_ok(self, app, client, db_session):
        manager = create_test_user(db_session, email='mgr@test.com', role=UserRole.MANAGER)
        db_session.commit()

        resp = _create_group(client, _auth(app, manager), name='Backend', description='Equipo')
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['group']['name'] == 'Backend'
        assert data['group']['member_count'] == 1
        # El creador aparece como OWNER
        members = data['group']['members']
        assert len(members) == 1
        assert members[0]['user_id'] == manager.id
        assert members[0]['role_in_group'] == 'OWNER'

    def test_create_group_as_admin_ok(self, app, client, db_session):
        admin = create_test_user(db_session, email='adm@test.com', role=UserRole.ADMIN)
        db_session.commit()
        resp = _create_group(client, _auth(app, admin))
        assert resp.status_code == 201

    def test_create_group_as_user_forbidden(self, app, client, db_session):
        user = create_test_user(db_session, email='plain@test.com', role=UserRole.USER)
        db_session.commit()
        resp = _create_group(client, _auth(app, user))
        assert resp.status_code == 403

    def test_create_group_requires_name(self, app, client, db_session):
        manager = create_test_user(db_session, email='mgr2@test.com', role=UserRole.MANAGER)
        db_session.commit()
        resp = client.post('/api/groups', json={'name': '   '}, headers=_auth(app, manager))
        assert resp.status_code == 400


class TestListGroups:
    """GET /api/groups"""

    def test_list_returns_only_groups_where_member(self, app, client, db_session):
        alice = create_test_user(db_session, email='a@test.com', role=UserRole.MANAGER)
        bob = create_test_user(db_session, email='b@test.com', role=UserRole.MANAGER)
        db_session.commit()

        _create_group(client, _auth(app, alice), name='Solo Alice')
        _create_group(client, _auth(app, bob), name='Solo Bob')

        resp = client.get('/api/groups', headers=_auth(app, alice))
        assert resp.status_code == 200
        names = [g['name'] for g in resp.get_json()['groups']]
        assert 'Solo Alice' in names
        assert 'Solo Bob' not in names


class TestGetGroup:
    """GET /api/groups/<id>"""

    def test_non_member_gets_404(self, app, client, db_session):
        owner = create_test_user(db_session, email='own@test.com', role=UserRole.MANAGER)
        outsider = create_test_user(db_session, email='out@test.com', role=UserRole.USER)
        db_session.commit()

        create_resp = _create_group(client, _auth(app, owner))
        gid = create_resp.get_json()['group']['id']

        resp = client.get(f'/api/groups/{gid}', headers=_auth(app, outsider))
        assert resp.status_code == 404

    def test_member_gets_group_with_members(self, app, client, db_session):
        owner = create_test_user(db_session, email='o2@test.com', role=UserRole.MANAGER)
        db_session.commit()
        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']

        resp = client.get(f'/api/groups/{gid}', headers=_auth(app, owner))
        assert resp.status_code == 200
        assert len(resp.get_json()['group']['members']) == 1


class TestUpdateGroup:
    """PUT /api/groups/<id>"""

    def test_update_requires_admin_or_owner_role_in_group(self, app, client, db_session):
        owner = create_test_user(db_session, email='ow@test.com', role=UserRole.MANAGER)
        other = create_test_user(db_session, email='ot@test.com', role=UserRole.MANAGER)
        db_session.commit()
        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']

        # Añadir other como MEMBER (no puede editar)
        client.post(f'/api/groups/{gid}/members',
                    json={'user_id': other.id, 'role_in_group': 'MEMBER'},
                    headers=_auth(app, owner))

        resp = client.put(f'/api/groups/{gid}', json={'name': 'Nuevo'},
                          headers=_auth(app, other))
        assert resp.status_code == 403

    def test_owner_can_update_name(self, app, client, db_session):
        owner = create_test_user(db_session, email='ow2@test.com', role=UserRole.MANAGER)
        db_session.commit()
        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']

        resp = client.put(f'/api/groups/{gid}', json={'name': 'Renombrado'},
                          headers=_auth(app, owner))
        assert resp.status_code == 200
        assert resp.get_json()['group']['name'] == 'Renombrado'


class TestDeleteGroup:
    """DELETE /api/groups/<id>"""

    def test_only_owner_can_delete(self, app, client, db_session):
        owner = create_test_user(db_session, email='del1@test.com', role=UserRole.MANAGER)
        admin_in_group = create_test_user(db_session, email='del2@test.com', role=UserRole.MANAGER)
        db_session.commit()
        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']

        client.post(f'/api/groups/{gid}/members',
                    json={'user_id': admin_in_group.id, 'role_in_group': 'ADMIN'},
                    headers=_auth(app, owner))

        # ADMIN (dentro del grupo) no puede borrar — solo OWNER
        resp = client.delete(f'/api/groups/{gid}', headers=_auth(app, admin_in_group))
        assert resp.status_code == 403

        resp = client.delete(f'/api/groups/{gid}', headers=_auth(app, owner))
        assert resp.status_code == 200

    def test_delete_cascades_memberships(self, app, client, db_session):
        owner = create_test_user(db_session, email='del3@test.com', role=UserRole.MANAGER)
        member = create_test_user(db_session, email='del4@test.com', role=UserRole.USER)
        db_session.commit()
        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']
        client.post(f'/api/groups/{gid}/members',
                    json={'user_id': member.id},
                    headers=_auth(app, owner))

        client.delete(f'/api/groups/{gid}', headers=_auth(app, owner))
        assert Group.query.get(gid) is None
        assert GroupMembership.query.filter_by(group_id=gid).count() == 0


class TestMembers:
    """POST / DELETE / PUT membros"""

    def test_add_member_unique_constraint(self, app, client, db_session):
        owner = create_test_user(db_session, email='m1@test.com', role=UserRole.MANAGER)
        target = create_test_user(db_session, email='m2@test.com', role=UserRole.USER)
        db_session.commit()
        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']

        r1 = client.post(f'/api/groups/{gid}/members',
                         json={'user_id': target.id},
                         headers=_auth(app, owner))
        assert r1.status_code == 201

        r2 = client.post(f'/api/groups/{gid}/members',
                         json={'user_id': target.id},
                         headers=_auth(app, owner))
        assert r2.status_code == 400

    def test_add_inactive_user_rejected(self, app, client, db_session):
        owner = create_test_user(db_session, email='m3@test.com', role=UserRole.MANAGER)
        inactive = create_test_user(db_session, email='m4@test.com', role=UserRole.USER)
        inactive.is_active = False
        db_session.commit()
        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']

        resp = client.post(f'/api/groups/{gid}/members',
                           json={'user_id': inactive.id},
                           headers=_auth(app, owner))
        assert resp.status_code == 404

    def test_remove_only_owner_forbidden(self, app, client, db_session):
        owner = create_test_user(db_session, email='m5@test.com', role=UserRole.MANAGER)
        db_session.commit()
        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']

        resp = client.delete(f'/api/groups/{gid}/members/{owner.id}',
                             headers=_auth(app, owner))
        assert resp.status_code == 400

    def test_change_role_only_by_owner(self, app, client, db_session):
        owner = create_test_user(db_session, email='m6@test.com', role=UserRole.MANAGER)
        admin_in_group = create_test_user(db_session, email='m7@test.com', role=UserRole.MANAGER)
        member = create_test_user(db_session, email='m8@test.com', role=UserRole.USER)
        db_session.commit()
        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']

        client.post(f'/api/groups/{gid}/members',
                    json={'user_id': admin_in_group.id, 'role_in_group': 'ADMIN'},
                    headers=_auth(app, owner))
        client.post(f'/api/groups/{gid}/members',
                    json={'user_id': member.id, 'role_in_group': 'MEMBER'},
                    headers=_auth(app, owner))

        # ADMIN de grupo NO puede cambiar roles
        r1 = client.put(f'/api/groups/{gid}/members/{member.id}/role',
                        json={'role_in_group': 'READONLY'},
                        headers=_auth(app, admin_in_group))
        assert r1.status_code == 403

        # OWNER sí puede
        r2 = client.put(f'/api/groups/{gid}/members/{member.id}/role',
                        json={'role_in_group': 'READONLY'},
                        headers=_auth(app, owner))
        assert r2.status_code == 200
        assert r2.get_json()['membership']['role_in_group'] == 'READONLY'

    def test_cannot_demote_only_owner(self, app, client, db_session):
        owner = create_test_user(db_session, email='m9@test.com', role=UserRole.MANAGER)
        db_session.commit()
        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']

        resp = client.put(f'/api/groups/{gid}/members/{owner.id}/role',
                          json={'role_in_group': 'MEMBER'},
                          headers=_auth(app, owner))
        assert resp.status_code == 400


class TestAudit:
    """Verifica que las mutaciones dejan rastro en AuditLog."""

    def test_audit_log_entries_on_group_events(self, app, client, db_session):
        owner = create_test_user(db_session, email='aud1@test.com', role=UserRole.MANAGER)
        target = create_test_user(db_session, email='aud2@test.com', role=UserRole.USER)
        db_session.commit()

        gid = _create_group(client, _auth(app, owner)).get_json()['group']['id']
        client.post(f'/api/groups/{gid}/members',
                    json={'user_id': target.id},
                    headers=_auth(app, owner))
        client.delete(f'/api/groups/{gid}/members/{target.id}',
                      headers=_auth(app, owner))
        client.delete(f'/api/groups/{gid}', headers=_auth(app, owner))

        actions = [
            a.action for a in AuditLog.query.filter_by(resource_type='GROUP').all()
        ]
        assert 'GROUP_CREATED' in actions
        assert 'MEMBER_ADDED' in actions
        assert 'MEMBER_REMOVED' in actions
        assert 'GROUP_DELETED' in actions
