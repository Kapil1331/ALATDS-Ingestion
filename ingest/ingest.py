import os
import csv
import requests, time
from itertools import zip_longest
import json

CSV_DIR = os.path.join(os.path.dirname(__file__), 'CSV')
API_URL = 'http://127.0.0.1:8000/log/ingest/'  # Removed {logtype} from URL

SCHEMAS = {
    'device': ['session_id', 'datetime', 'user', 'pc', 'activity'],
    'http': ['session_id', 'datetime', 'user', 'pc', 'url'],
    'logon': ['session_id', 'datetime', 'user', 'pc', 'activity'],
    'all_datas_f': ['method', 'path', 'body', 'single_q', 'double_q', 'dashes', 'braces', 'spaces', 'percentages', 'semicolons', 'angle_brackets', 'special_chars', 'path_length', 'body_length', 'badwords_count', 'class']
}

def split_datetime(dt):
    parts = dt.split()
    return (parts[0], parts[1]) if len(parts) == 2 else (dt, '')

def load_csv_rows(filepath):
    filename = os.path.splitext(os.path.basename(filepath))[0]
    schema = SCHEMAS.get(filename)
    if not schema:
        print(f"⚠️ Skipping {filepath} (no schema found)")
        return
    with open(filepath, newline='') as csvfile:
        reader = csv.DictReader(csvfile, fieldnames=schema)
        next(reader)  # skip header
        for row in reader:
            yield filename, row

def send_data(filename, row):
    data = {'logtype': filename}
    
    if filename == 'all_datas_f':
        # Send ALL WSL columns as-is
        data.update(row)
    else:
        # For other logs, split datetime and include all fields
        date, time = split_datetime(row['datetime'])
        data.update({
            **row,  # Include all original fields
            'date': date,
            'time': time,
        })
        # Remove the original datetime to avoid duplication
        data.pop('datetime', None)

    try:
        print(f"📤 Preparing to send data to {API_URL}:")
        print(json.dumps(data, indent=2))  # Pretty-print the JSON data
        
        # hitting endpoint
        response = requests.post(API_URL, json=data)
        response.raise_for_status()
        print(f"✅ Sent row to {API_URL}: {data}")
    except Exception as e:
        print(f"❌ Error sending row to {API_URL}: {e}")

def ingest_round_robin():
    csv_files = [os.path.join(CSV_DIR, f) for f in os.listdir(CSV_DIR) if f.endswith('.csv')]
    iterators = [load_csv_rows(f) for f in csv_files]
    for rows in zip_longest(*iterators, fillvalue=None):
        for row_data in rows:
            if row_data is None:
                continue
            filename, row = row_data
            send_data(filename, row)
    
            time.sleep(0.1)

if __name__ == "__main__":
    ingest_round_robin()