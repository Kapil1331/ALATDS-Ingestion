import sqlite3
import pandas as pd
from typing import Optional
import json

DB_FILE = "logs.db"
RESULTS_FILE = "results.db"

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # For dict-like access
    return conn

def get_results_connection():
    conn = sqlite3.connect(RESULTS_FILE)
    conn.row_factory = sqlite3.Row  # For dict-like access
    return conn

def create_result_tables():
    conn = get_results_connection()
    cursor = conn.cursor()

    # WSL predictions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS wsl_predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_type TEXT,
        log_id TEXT,
        is_threat INTEGER,
        threat_level TEXT,
        log JSON
    )
    """)
    
    # Windows Event Log predictions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS win_event_predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_type TEXT,
        log_id TEXT,
        is_threat INTEGER,
        threat_level TEXT,
        log JSON
    )
    """)
    
    # Network Event predictions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_type TEXT,
        log_id TEXT,
        is_threat INTEGER,
        threat_level TEXT,
        log JSON
    )
    """)

    conn.commit()
    conn.close()

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
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS "netflow_day-02" (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        logtype TEXT,
        Time TEXT,
        Duration TEXT,
        SrcDevice TEXT,
        DstDevice TEXT,
        Protocol TEXT,
        SrcPort TEXT,
        DstPort TEXT,
        SrcPackets TEXT,
        DstPackets TEXT,
        SrcBytes TEXT,
        DstBytes TEXT,
        date TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS "wls_day-02" (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        logtype TEXT,
        UserName TEXT,
        EventID INTEGER,
        LogHost TEXT,
        LogonID TEXT,
        DomainName TEXT,
        LogonTypeDescription TEXT,
        Source TEXT,
        AuthenticationPackage TEXT,
        Time INTEGER,
        LogonType INTEGER,
        date TEXT
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


def insert_netflow_day_02_bulk(logs: list[dict]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executemany("""
        INSERT INTO "netflow_day-02" (
            logtype, Time, Duration, SrcDevice, DstDevice, Protocol,
            SrcPort, DstPort, SrcPackets, DstPackets, SrcBytes, DstBytes,
            date
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        (
            log["logtype"],
            log["Time"],
            log["Duration"],
            log["SrcDevice"],
            log["DstDevice"],
            log["Protocol"],
            log["SrcPort"],
            log["DstPort"],
            log["SrcPackets"],
            log["DstPackets"],
            log["SrcBytes"],
            log["DstBytes"],
            log["date"],
        )
        for log in logs
    ])
    conn.commit()
    conn.close()


def insert_wls_day_02_bulk(logs: list[dict]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executemany("""
        INSERT INTO "wls_day-02" (
            logtype, UserName, EventID, LogHost, LogonID, DomainName,
            ParentProcessName, ParentProcessID, ProcessName,
            Time, ProcessID, date
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        (
            log["logtype"],
            log["UserName"],
            log["EventID"],
            log["LogHost"],
            log["LogonID"],
            log["DomainName"],
            log["ParentProcessName"],
            log["ParentProcessID"],
            log["ProcessName"],
            log["Time"],
            log["ProcessID"],
            log["date"],
        )
        for log in logs
    ])
    conn.commit()
    conn.close()


def insert_wsl_predictions_bulk(logs: list[dict]):
    conn = get_results_connection()  # Use results database instead of logs database
    cursor = conn.cursor()
    try:
        cursor.executemany("""
            INSERT INTO wsl_predictions (
                log_type, log_id, is_threat, threat_level, log
            )
            VALUES (?, ?, ?, ?, ?)
        """, [
            (
                log["log_type"],
                log["log_id"],
                1 if log["is_threat"] else 0,  # Convert boolean to integer
                log.get("threat_level", "unknown"),  # Get threat_level with default
                json.dumps(log),  # Convert dict to JSON string
            )
            for log in logs
        ])
        conn.commit()
    except Exception as e:
        print(f"Error inserting predictions: {str(e)}")
        raise
    finally:
        conn.close()

def insert_win_event_predictions_bulk(logs: list[dict]):
    conn = get_results_connection()
    cursor = conn.cursor()
    try:
        cursor.executemany("""
            INSERT INTO win_event_predictions (
                log_type, log_id, is_threat, threat_level, log
            )
            VALUES (?, ?, ?, ?, ?)
        """, [
            (
                log["log_type"],
                log["log_id"],
                1 if log["is_threat"] else 0,  # Convert boolean to integer
                log.get("threat_level", "unknown"),  # Get threat_level with default
                json.dumps(log),  # Convert dict to JSON string
            )
            for log in logs
        ])
        conn.commit()
    except Exception as e:
        print(f"Error inserting win event predictions: {str(e)}")
        raise
    finally:
        conn.close()

def insert_network_predictions_bulk(logs: list[dict]):
    conn = get_results_connection()
    cursor = conn.cursor()
    try:
        cursor.executemany("""
            INSERT INTO network_predictions (
                log_type, log_id, is_threat, threat_level, log
            )
            VALUES (?, ?, ?, ?, ?)
        """, [
            (
                log["log_type"],
                log["log_id"],
                1 if log["is_threat"] else 0,  # Convert boolean to integer
                log.get("threat_level", "unknown"),  # Get threat_level with default
                json.dumps(log),  # Convert dict to JSON string
            )
            for log in logs
        ])
        conn.commit()
    except Exception as e:
        print(f"Error inserting network predictions: {str(e)}")
        raise
    finally:
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