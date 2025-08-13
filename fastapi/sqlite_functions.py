import sqlite3
import pandas as pd
from typing import Optional

DB_FILE = "logs.db"

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # For dict-like access
    return conn


# Create tables on INIT
def create_tables():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        date TEXT,
        time TEXT,
        user TEXT,
        pc TEXT,
        activity TEXT
    )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS http_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        date TEXT,
        time TEXT,
        user TEXT,
        pc TEXT,
        url TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logon_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        date TEXT,
        time TEXT,
        user TEXT,
        pc TEXT,
        activity TEXT
    )
    """)

    conn.commit()
    conn.close()


# Log insertion fucntions
def insert_device_log(log_doc: dict):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO device_logs (session_id, date, time, user, pc, activity)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        log_doc.get("session_id"),
        log_doc.get("date"),
        log_doc.get("time"),
        log_doc.get("user"),
        log_doc.get("pc"),
        log_doc.get("activity"),
    ))
    conn.commit()
    conn.close()


def insert_http_log(log_doc: dict):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO http_logs (session_id, date, time, user, pc, url)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        log_doc.get("session_id"),
        log_doc.get("date"),
        log_doc.get("time"),
        log_doc.get("user"),
        log_doc.get("pc"),
        log_doc.get("url"),
    ))
    conn.commit()
    conn.close()


def insert_logon_log(log_doc: dict):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logon_logs (session_id, date, time, user, pc, activity)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        log_doc.get("session_id"),
        log_doc.get("date"),
        log_doc.get("time"),
        log_doc.get("user"),
        log_doc.get("pc"),
        log_doc.get("activity"),
    ))
    conn.commit()
    conn.close()


# Fetch the logs from the db
def fetch_logs(logtype: str, limit: Optional[int] = None) -> pd.DataFrame:
    conn = get_connection()
    cursor = conn.cursor()
    
    table_map = {
        "device": "device_logs",
        "http": "http_logs",
        "logon": "logon_logs",
    }
    
    table = table_map.get(logtype)
    if not table:
        raise ValueError(f"Invalid logtype '{logtype}'")

    query = f"SELECT * FROM {table} ORDER BY id DESC"
    if limit is not None:
        query += f" LIMIT {limit}"

        
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        return pd.DataFrame()
    
    df = pd.DataFrame([dict(row) for row in rows])
    return df


def get_log_src():
    with get_connection() as conn:
        # cursor = conn.cursor()

        # cursor.execute("SELECT COUNT(*) FROM logon_logs")
        # logon_count = cursor.fetchone()[0]

        # cursor.execute("SELECT COUNT(*) FROM http_logs")
        # http_count = cursor.fetchone()[0]

        # cursor.execute("SELECT COUNT(*) FROM device_logs")
        # device_count = cursor.fetchone()[0]

        # cursor.execute("SELECT COUNT(*) FROM wsl_logs")
        # wsl_count = cursor.fetchone()[0]

        logon_count = 5
        http_count = 10
        device_count = 15
        wsl_count = 20

    return {
        "src_dist": {
            "logon_count": logon_count,
            "http_count": http_count,
            "device_count": device_count,
            "wsl_count": wsl_count,
            "total": logon_count + http_count + device_count + wsl_count
        }
    }