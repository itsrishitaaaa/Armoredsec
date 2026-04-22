import sqlite3


def connect_db():
    return sqlite3.connect("armoredsec.db")


def create_tables():

    conn = connect_db()
    cursor = conn.cursor()

    # ---------------- USERS TABLE ----------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    # ---------------- ALERTS TABLE ----------------
    # Now alerts are stored per user
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        issue TEXT,
        severity TEXT,
        solution TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close() 