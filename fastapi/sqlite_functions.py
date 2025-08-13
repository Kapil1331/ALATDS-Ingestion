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


# Insert in bulks
def insert_device_log_bulk(logs: list[dict]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executemany("""
        INSERT INTO device_logs (session_id, date, time, user, pc, activity)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [(log["session_id"], log["date"], log["time"], log["user"], log["pc"], log["activity"]) for log in logs])
    conn.commit()
    conn.close()


def insert_http_log_bulk(logs: list[dict]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executemany("""
        INSERT INTO http_logs (session_id, date, time, user, pc, url)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [(log["session_id"], log["date"], log["time"], log["user"], log["pc"], log["url"]) for log in logs])
    conn.commit()
    conn.close()


def insert_logon_log_bulk(logs: list[dict]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executemany("""
        INSERT INTO logon_logs (session_id, date, time, user, pc, activity)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [(log["session_id"], log["date"], log["time"], log["user"], log["pc"], log["activity"]) for log in logs])
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