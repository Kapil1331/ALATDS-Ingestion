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

    # Employee Analysis Results table (for anomalies)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS emp_analysis_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_type TEXT NOT NULL,
        log_id INTEGER NOT NULL,
        is_threat INTEGER DEFAULT 0,
        log TEXT
    )
    """)

    # Employee Activity Correlations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS emp_activity_correlations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        primary_event TEXT NOT NULL,
        primary_timestamp TEXT,
        user TEXT NOT NULL,
        related_events TEXT,
        time_window_mins REAL,
        analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        
        -- Indexes for faster querying
        CONSTRAINT idx_user_time UNIQUE (user, primary_timestamp)
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

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (pd.Timestamp, pd._libs.tslibs.timestamps.Timestamp)):
        return obj.isoformat()
    if isinstance(obj, (pd.Series, pd.DataFrame)):
        return obj.to_dict()
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    if hasattr(obj, 'isoformat'):  # For datetime objects
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def insert_emp_analysis_results_bulk(results_df: pd.DataFrame):
    conn = get_results_connection()
    cursor = conn.cursor()
    import os
    print("Using results DB file:", os.path.abspath(RESULTS_FILE))

    try:
        # Debug: Print the DataFrame structure
        print("DataFrame columns:", results_df.columns.tolist())
        print("First row sample:", results_df.iloc[0].to_dict())
        
        # Convert DataFrame to list of dictionaries
        results = results_df.to_dict('records')
        
        # Prepare data for insertion
        insert_data = []
        for row in results:
            try:
                # Ensure the log dictionary has serializable datetime
                if 'log' in row and 'datetime' in row['log']:
                    row['log']['datetime'] = str(row['log']['datetime'])
                
                insert_data.append((
                    row.get('log_type'),
                    int(row.get('log_id')),  # Using log_id instead of id
                    1 if row.get('is_threat') else 0,
                    json.dumps(row.get('log'), default=str)  # Use default=str for safety
                ))
            except Exception as row_error:
                print(f"Error processing row: {row_error}")
                print("Problematic row:", row)
                raise
        
        # Debug: Print the SQL that will be executed
        print(f"Preparing to insert {len(insert_data)} records")
        
        # Execute the insertion
        cursor.executemany("""
            INSERT INTO emp_analysis_results (
                log_type, log_id, is_threat, log
            )
            VALUES (?, ?, ?, ?)
        """, insert_data)
        
        conn.commit()
        print(f"Successfully inserted {len(insert_data)} records")
        cursor.execute("SELECT COUNT(*) FROM emp_analysis_results")
        print("Row count immediately after insert:", cursor.fetchone()[0])
        
    except Exception as e:
        conn.rollback()
        print(f"Error inserting employee analysis results: {str(e)}")
        # Get more detailed error information
        try:
            cursor.execute("PRAGMA table_info(emp_analysis_results)")
            print("Current table schema:", cursor.fetchall())
        except:
            pass
        raise
    finally:
        conn.close()

def insert_emp_activity_correlations_bulk(correlations_df: pd.DataFrame):
    conn = get_results_connection()
    cursor = conn.cursor()
    try:
        # Convert DataFrame to list of dictionaries
        correlations = correlations_df.to_dict('records')
        cursor.executemany("""
            INSERT INTO emp_activity_correlations (
                primary_event, primary_timestamp, user,
                related_events, time_window_mins
            )
            VALUES (?, ?, ?, ?, ?)
        """, [
            (
                row.get("primary_event"),
                row.get("primary_timestamp"),
                row.get("user"),
                json.dumps(row.get("related_events"), default=json_serial),
                row.get("time_window_mins")
            )
            for row in correlations
        ])
        conn.commit()
    except Exception as e:
        print(f"Error inserting employee activity correlations: {str(e)}")
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
