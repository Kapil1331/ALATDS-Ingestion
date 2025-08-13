from sqlite_functions import insert_device_log, insert_http_log, insert_logon_log

def handle_device_log(row: dict):
    insert_device_log(row)

def handle_http_log(row: dict):
    insert_http_log(row)

def handle_logon_log(row: dict):
    insert_logon_log(row)