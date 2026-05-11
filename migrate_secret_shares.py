"""
Migración: crear la tabla `secret_shares` para soportar RF04 (compartición
de secretos con usuarios y grupos).

Idempotente — puede ejecutarse varias veces sin efectos colaterales.
Soporta SQLite (desarrollo) y PostgreSQL/MySQL (producción).
"""

import os
import sys

# Asegurar que el directorio raíz del proyecto está en sys.path
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app import create_app  # noqa: E402
from models import db  # noqa: E402
from sqlalchemy import inspect, text  # noqa: E402


SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS secret_shares (
    id VARCHAR(36) PRIMARY KEY,
    secret_id VARCHAR(36) NOT NULL,
    shared_by_id INTEGER NOT NULL,
    shared_with_user_id INTEGER NOT NULL,
    shared_with_group_id VARCHAR(36),
    encrypted_aes_key_for_recipient TEXT NOT NULL,
    can_read BOOLEAN NOT NULL DEFAULT 1,
    can_edit BOOLEAN NOT NULL DEFAULT 0,
    can_share BOOLEAN NOT NULL DEFAULT 0,
    shared_at DATETIME,
    expires_at DATETIME,
    is_revoked BOOLEAN NOT NULL DEFAULT 0,
    revoked_at DATETIME,
    FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by_id) REFERENCES users(id),
    FOREIGN KEY (shared_with_user_id) REFERENCES users(id),
    FOREIGN KEY (shared_with_group_id) REFERENCES groups(id) ON DELETE SET NULL,
    CONSTRAINT uq_share_secret_user_group UNIQUE (secret_id, shared_with_user_id, shared_with_group_id)
);
"""

SQLITE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_secret_shares_secret ON secret_shares(secret_id);",
    "CREATE INDEX IF NOT EXISTS ix_secret_shares_user ON secret_shares(shared_with_user_id);",
    "CREATE INDEX IF NOT EXISTS ix_secret_shares_group ON secret_shares(shared_with_group_id);",
]


def run() -> None:
    app = create_app()
    with app.app_context():
        engine = db.engine
        dialect = engine.dialect.name
        inspector = inspect(engine)

        if 'secret_shares' in inspector.get_table_names():
            print('[migrate_secret_shares] Tabla secret_shares ya existe — nada que hacer.')
            return

        print(f'[migrate_secret_shares] Creando tabla secret_shares (dialect={dialect})…')

        if dialect == 'sqlite':
            with engine.begin() as conn:
                conn.execute(text(SQLITE_DDL))
                for stmt in SQLITE_INDEXES:
                    conn.execute(text(stmt))
        else:
            # Para PostgreSQL/MySQL nos apoyamos en SQLAlchemy con la definición del modelo
            from models import SecretShare  # noqa: F401  (registrar modelo)
            db.metadata.tables['secret_shares'].create(bind=engine)

        print('[migrate_secret_shares] OK — tabla y índices creados.')


if __name__ == '__main__':
    run()
