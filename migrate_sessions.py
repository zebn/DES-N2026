"""
Migración: crear la tabla `sessions` para soportar RF05 (gestión de sesiones).

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
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_jti VARCHAR(64) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    device_info VARCHAR(255),
    created_at DATETIME NOT NULL,
    last_activity DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT 0,
    revoked_at DATETIME,
    revoked_reason VARCHAR(120),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
"""

SQLITE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id);",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_sessions_jti ON sessions(token_jti);",
]


def run() -> None:
    app = create_app()
    with app.app_context():
        engine = db.engine
        dialect = engine.dialect.name
        inspector = inspect(engine)

        if 'sessions' in inspector.get_table_names():
            print('[migrate_sessions] Tabla sessions ya existe — nada que hacer.')
            return

        print(f'[migrate_sessions] Creando tabla sessions (dialect={dialect})…')

        if dialect == 'sqlite':
            with engine.begin() as conn:
                conn.execute(text(SQLITE_DDL))
                for stmt in SQLITE_INDEXES:
                    conn.execute(text(stmt))
        else:
            # Para PostgreSQL/MySQL nos apoyamos en SQLAlchemy con la definición del modelo
            from models import Session  # noqa: F401  (registrar modelo)
            db.metadata.tables['sessions'].create(bind=engine)

        print('[migrate_sessions] OK — tabla y índices creados.')


if __name__ == '__main__':
    run()
