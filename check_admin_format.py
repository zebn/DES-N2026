import sqlite3
import json

conn = sqlite3.connect('instance/database.db')
cursor = conn.cursor()

cursor.execute('SELECT id, email, key_derivation_params FROM users WHERE email="admin@admin.com"')
row = cursor.fetchone()

if row:
    params = json.loads(row[2])
    print('✅ Admin encontrado:')
    print(f'   User ID: {row[0]}')
    print(f'   Email: {row[1]}')
    print(f'   Params keys: {list(params.keys())}')
    print(f'   Has counter: {"counter" in params}')
    print(f'   Has iv: {"iv" in params}')
    
    if 'counter' in params:
        print('✅ FORMATO CORRECTO: AES-CTR con counter')
    elif 'iv' in params:
        print('⚠️ FORMATO ANTIGUO: AES-CBC con IV')
    else:
        print('❌ FORMATO DESCONOCIDO')
else:
    print('❌ Admin no encontrado')

conn.close()
