from app import app
from models import db, User
with app.app_context():
    u = User.query.filter_by(email="admin@admin.com").first()
    if u:
        print(f"FOUND id={u.id} email={u.email} failed_attempts={u.failed_login_attempts} locked_until={u.locked_until} is_active={u.is_active} role={u.role}")
    else:
        print("NOT FOUND - admin does not exist in DB")
    total = User.query.count()
    print(f"Total users in DB: {total}")
