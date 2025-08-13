import os
import csv
import requests, time
from itertools import zip_longest
import json, datetime

CSV_DIR = os.path.join(os.path.dirname(__file__), 'CSV')

API_URL = 'http://127.0.0.1:8000/log/ingest/'
API_URL = 'http://10.1.232.5:8000/log/ingest/'

SCHEMAS = {
    'device': ['session_id', 'datetime', 'user', 'pc', 'activity'],
    'http': ['session_id', 'datetime', 'user', 'pc', 'url'],
    'logon': ['session_id', 'datetime', 'user', 'pc', 'activity'],
    'all_datas_f': [
        'method', 'path', 'body', 'single_q', 'double_q', 'dashes',
        'braces', 'spaces', 'percentages', 'semicolons', 'angle_brackets',
        'special_chars', 'path_length', 'body_length', 'badwords_count', 'class'
    ],
    'netflow_day-02': [
        'Time', 'Duration', 'SrcDevice', 'DstDevice', 'Protocol',
        'SrcPort', 'DstPort', 'SrcPackets', 'DstPackets', 'SrcBytes', 'DstBytes'
    ],
    'wls_day-02': None  # JSON lines format, so no fixed schema
}

def split_datetime(dt):
    parts = dt.split()
    return (parts[0], parts[1]) if len(parts) == 2 else (dt, '')

def load_file_rows(filepath):
    filename = os.path.splitext(os.path.basename(filepath))[0]

    # JSON lines format
    if filename == 'wls_day-02':
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    row = json.loads(line)
                    yield filename, row
        return

    # CSV format
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
        data.update(row)
    elif filename == 'netflow_day-02':
        data.update(row)
        try:
            ts = int(row['Time'])
            date = datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d')
            time_ = datetime.datetime.utcfromtimestamp(ts).strftime('%H:%M:%S')
            data['date'] = date
        except:
            pass
    elif filename == 'wls_day-02':
        data.update(row)
        # Convert Time (epoch) to date/time if possible
        try:
            ts = int(row['Time'])
            date = datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d')
            data['date'] = date
        except:
            pass
    else:
        date, time = split_datetime(row['datetime'])
        data.update({
            **row,
            'date': date,
            'time': time,
        })
        data.pop('datetime', None)

    try:
        print(f"📤 Preparing to send data to {API_URL}:")
        print(json.dumps(data, indent=2))

        # Uncomment to actually send
        response = requests.post(API_URL, json=data)
        response.raise_for_status()
        print(f"✅ Sent row to {API_URL}: {data}")
    except Exception as e:
        print(f"❌ Error sending row to {API_URL}: {e}")

def ingest_round_robin():
    files = [os.path.join(CSV_DIR, f) for f in os.listdir(CSV_DIR)]
    iterators = [load_file_rows(f) for f in files]
    for rows in zip_longest(*iterators, fillvalue=None):
        for row_data in rows:
            if row_data is None:
                continue
            filename, row = row_data
            send_data(filename, row)
            time.sleep(0.1)

if __name__ == "__main__":
    ingest_round_robin()
