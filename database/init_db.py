"""
Run locally:  python database/init_db.py
On Render:    Runs automatically via build command
"""
import os, sys

DATABASE_URL = os.environ.get("DATABASE_URL")
SQL_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

with open(SQL_PATH, "r") as f:
    sql = f.read()

if DATABASE_URL:
    import psycopg2
    # PostgreSQL on Render — run statement by statement
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    cur = conn.cursor()
    statements = [s.strip() for s in sql.split(";") if s.strip()]
    for stmt in statements:
        try:
            cur.execute(stmt)
        except Exception as e:
            print(f"  Skipped: {e}")
    conn.close()
    print("✅ PostgreSQL database initialised on Render!")
else:
    import sqlite3
    DB_PATH = os.path.join(os.path.dirname(__file__), "neataura.db")
    # SQLite locally — replace SERIAL with INTEGER for compatibility
    sql_lite = sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
    sql_lite = sql_lite.replace("ON CONFLICT DO NOTHING", "")
    # Fix INSERT statements to use INSERT OR IGNORE
    sql_lite = sql_lite.replace("INSERT INTO services", "INSERT OR IGNORE INTO services")
    sql_lite = sql_lite.replace("INSERT INTO workers", "INSERT OR IGNORE INTO workers")
    sql_lite = sql_lite.replace("INSERT INTO worker_services", "INSERT OR IGNORE INTO worker_services")
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(sql_lite)
    conn.commit()
    conn.close()
    print(f"✅ SQLite database created at {DB_PATH}")

if __name__ == "__main__":
    pass