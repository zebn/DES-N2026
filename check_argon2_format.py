import sqlite3
import json

conn = sqlite3.connect('instance/database.db')
cursor = conn.cursor()

cursor.execute("SELECT id, email, key_derivation_params FROM users WHERE email='admin@admin.com'")
row = cursor.fetchone()

if row:
    print('✅ Admin encontrado:')
    print(f'   User ID: {row[0]}')
    print(f'   Email: {row[1]}')
    
    params = json.loads(row[2])
    print(f'   Params keys: {list(params.keys())}')
    print(f'   Algorithm: {params.get("algorithm")}')
    print(f'   Has time_cost: {("time_cost" in params)}')
    print(f'   Has memory_cost: {("memory_cost" in params)}')
    print(f'   Has parallelism: {("parallelism" in params)}')
    print(f'   Has counter: {("counter" in params)}')
    print(f'   Has hash_len: {("hash_len" in params)}')
    
    if params.get('algorithm') == 'Argon2id':
        print('\n✅ FORMATO CORRECTO: Argon2id')
        print(f'   Time cost: {params.get("time_cost")}')
        print(f'   Memory cost: {params.get("memory_cost")} KB')
        print(f'   Parallelism: {params.get("parallelism")}')
    else:
        print(f'\n❌ FORMATO INCORRECTO: {params.get("algorithm")}')
else:
    print('❌ Admin no encontrado')

conn.close()
