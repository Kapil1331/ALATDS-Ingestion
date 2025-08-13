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

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS all_datas_f_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        logtype TEXT,
        method TEXT,
        path TEXT,
        body TEXT,
        single_q TEXT,
        double_q TEXT,
        dashes TEXT,
        braces TEXT,
        spaces TEXT,
        percentages TEXT,
        semicolons TEXT,
        angle_brackets TEXT,
        special_chars TEXT,
        path_length TEXT,
        body_length TEXT,
        badwords_count TEXT,
        class TEXT
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


def insert_all_datas_f_bulk(logs: list[dict]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executemany("""
        INSERT INTO all_datas_f_logs (
            logtype, method, path, body,
            single_q, double_q, dashes, braces, spaces,
            percentages, semicolons, angle_brackets, special_chars,
            path_length, body_length, badwords_count, class
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        (
            log["logtype"],
            log["method"],
            log["path"],
            log["body"],
            log["single_q"],
            log["double_q"],
            log["dashes"],
            log["braces"],
            log["spaces"],
            log["percentages"],
            log["semicolons"],
            log["angle_brackets"],
            log["special_chars"],
            log["path_length"],
            log["body_length"],
            log["badwords_count"],
            log["class"]
        )
        for log in logs
    ])
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