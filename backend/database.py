import sqlite3
import os

# Get correct base directory (backend folder)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Proper DB path
DB_PATH = os.path.join(BASE_DIR, "armoredsec.db")


def connect_db():
    return sqlite3.connect(DB_PATH)


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