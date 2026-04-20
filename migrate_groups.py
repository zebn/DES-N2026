#!/usr/bin/env python3
"""
Migración: Crear tablas `groups` y `group_memberships` (RF03).

Uso:
    python migrate_groups.py

Qué hace:
    1. Crea la tabla `groups` si no existe
    2. Crea la tabla `group_memberships` con UNIQUE(group_id, user_id)
    3. Añade índices sobre group_id y user_id
    4. Muestra resumen

Es idempotente: se puede ejecutar varias veces sin problema.
"""

import os
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'database.db')


def _table_exists(cursor, table):
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    )
    return cursor.fetchone() is not None


def _index_exists(cursor, index):
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name=?", (index,)
    )
    return cursor.fetchone() is not None


def migrate():
    if not os.path.exists(DB_PATH):
        print(f"❌ Base de datos no encontrada en: {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. Tabla groups
    if not _table_exists(cursor, 'groups'):
        print("➕ Creando tabla 'groups'...")
        cursor.execute("""
            CREATE TABLE groups (
                id VARCHAR(36) PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                created_by_id INTEGER NOT NULL,
                created_at DATETIME,
                updated_at DATETIME,
                FOREIGN KEY(created_by_id) REFERENCES users(id)
            )
        """)
        conn.commit()
        print("   ✅ Tabla 'groups' creada")
    else:
        print("ℹ️  La tabla 'groups' ya existe")

    # 2. Tabla group_memberships
    if not _table_exists(cursor, 'group_memberships'):
        print("➕ Creando tabla 'group_memberships'...")
        cursor.execute("""
            CREATE TABLE group_memberships (
                id VARCHAR(36) PRIMARY KEY,
                group_id VARCHAR(36) NOT NULL,
                user_id INTEGER NOT NULL,
                role_in_group VARCHAR(20) NOT NULL DEFAULT 'MEMBER',
                added_by_id INTEGER,
                joined_at DATETIME,
                CONSTRAINT uq_group_user UNIQUE (group_id, user_id),
                FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(added_by_id) REFERENCES users(id)
            )
        """)
        conn.commit()
        print("   ✅ Tabla 'group_memberships' creada")
    else:
        print("ℹ️  La tabla 'group_memberships' ya existe")

    # 3. Índices
    for idx_name, idx_sql in [
        ('ix_group_memberships_group_id',
         "CREATE INDEX ix_group_memberships_group_id ON group_memberships(group_id)"),
        ('ix_group_memberships_user_id',
         "CREATE INDEX ix_group_memberships_user_id ON group_memberships(user_id)"),
    ]:
        if not _index_exists(cursor, idx_name):
            cursor.execute(idx_sql)
            conn.commit()
            print(f"   ✅ Índice '{idx_name}' creado")

    # 4. Resumen
    cursor.execute("SELECT COUNT(*) FROM groups")
    groups_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM group_memberships")
    memberships_count = cursor.fetchone()[0]

    print("\n📊 Resumen:")
    print(f"   Grupos:      {groups_count}")
    print(f"   Membresías:  {memberships_count}")

    conn.close()
    print("\n✅ Migración completada exitosamente.")


if __name__ == '__main__':
    migrate()
