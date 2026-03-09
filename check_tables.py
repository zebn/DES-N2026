import sqlite3
conn = sqlite3.connect('instance/database.db')
c = conn.cursor()
rows = c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
print("Tables in DB:")
for r in rows:
    print(f"  - {r[0]}")
conn.close()
