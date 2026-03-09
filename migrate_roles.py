#!/usr/bin/env python3
"""
Migración: Añadir campo `role` (RBAC) a la tabla `users`.

Uso:
    python migrate_roles.py

Qué hace:
    1. Añade la columna `role` a la tabla `users` (si no existe)
    2. Migra datos existentes: is_admin=True → ADMIN, resto → USER
    3. Muestra resumen de la migración

Es idempotente: se puede ejecutar varias veces sin problema.
"""

import sqlite3
import sys
import os

# Ruta a la base de datos SQLite
DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'database.db')

VALID_ROLES = ('ADMIN', 'MANAGER', 'USER', 'AUDITOR')


def migrate():
    if not os.path.exists(DB_PATH):
        print(f"❌ Base de datos no encontrada en: {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Verificar si la columna 'role' ya existe
    cursor.execute("PRAGMA table_info(users)")
    columns = [col['name'] for col in cursor.fetchall()]

    if 'role' not in columns:
        print("➕ Añadiendo columna 'role' a la tabla 'users'...")
        cursor.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'USER' NOT NULL")
        conn.commit()
        print("   ✅ Columna 'role' creada con valor por defecto 'USER'")
    else:
        print("ℹ️  La columna 'role' ya existe en la tabla 'users'")

    # 2. Migrar datos: is_admin=True → ADMIN
    cursor.execute("UPDATE users SET role = 'ADMIN' WHERE is_admin = 1 AND (role IS NULL OR role = 'USER')")
    admin_count = cursor.rowcount
    conn.commit()

    if admin_count > 0:
        print(f"   🔄 {admin_count} usuario(s) con is_admin=True migrado(s) a rol ADMIN")

    # 3. Asegurar que todos tengan un rol válido
    cursor.execute("UPDATE users SET role = 'USER' WHERE role IS NULL OR role = ''")
    fixed = cursor.rowcount
    if fixed > 0:
        print(f"   🔧 {fixed} usuario(s) sin rol asignados a USER")

    conn.commit()

    # 4. Resumen
    print("\n📊 Resumen de roles:")
    for role in VALID_ROLES:
        cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE role = ?", (role,))
        count = cursor.fetchone()['cnt']
        print(f"   {role:10s}: {count} usuario(s)")

    cursor.execute("SELECT COUNT(*) as cnt FROM users")
    total = cursor.fetchone()['cnt']
    print(f"   {'TOTAL':10s}: {total} usuario(s)")

    conn.close()
    print("\n✅ Migración completada exitosamente.")


if __name__ == '__main__':
    migrate()
