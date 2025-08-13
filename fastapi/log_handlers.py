from sqlite_functions import insert_device_log, insert_http_log, insert_logon_log
from sqlite_functions import insert_device_log_bulk, insert_http_log_bulk, insert_logon_log_bulk

BATCH_SIZE = 10

device_log_count = 0
http_log_count = 0
logon_log_count = 0

device_log_buffer = []
http_log_buffer = []
logon_log_buffer = []

def handle_device_log(row: dict):
    global device_log_count
    device_log_count += 1

    device_log_buffer.append(row)
    if(device_log_count == BATCH_SIZE):
        # send to ml model 
        insert_device_logs_bulk(log_buffer)
        device_log_count = 0
        device_log_buffer.clear()

    insert_device_log(row)

def handle_http_log(row: dict):
    global http_log_count
    http_log_count += 1
    http_log_buffer.append(row)
    if(http_log_count == BATCH_SIZE):
        # send to ml model
        insert_http_logs_bulk(http_log_buffer)
        http_log_count = 0
        http_log_buffer.clear()

    insert_http_log(row)

def handle_logon_log(row: dict):
    global logon_log_count
    logon_log_count += 1
    logon_log_buffer.append(row)
    if(logon_log_count == BATCH_SIZE):
        # send to ml model
        insert_logon_logs_bulk(logon_log_buffer)
        logon_log_count = 0
        logon_log_buffer.clear()

    insert_logon_log(row)