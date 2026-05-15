#!/usr/bin/env python3
"""Проверка наличия и статуса admin аккаунта на Heroku"""

from app import app
from models import db, User

def main():
    with app.app_context():
        u = User.query.filter_by(email="admin@admin.com").first()
        if u:
            print(f"✓ ADMIN FOUND:")
            print(f"  ID: {u.id}")
            print(f"  Email: {u.email}")
            print(f"  Role: {u.role.value}")
            print(f"  Is Active: {u.is_active}")
            print(f"  Failed Attempts: {u.failed_login_attempts}")
            print(f"  Locked Until: {u.locked_until}")
            print(f"  Is Locked: {u.is_locked()}")
        else:
            print("✗ ADMIN NOT FOUND - need to create")
        
        total = User.query.count()
        print(f"\nTotal users in DB: {total}")

if __name__ == "__main__":
    main()
