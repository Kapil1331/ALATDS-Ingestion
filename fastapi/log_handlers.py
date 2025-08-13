from sqlite_functions import insert_device_log, insert_http_log, insert_logon_log
from sqlite_functions import insert_device_log_bulk, insert_http_log_bulk, insert_logon_log_bulk, insert_all_datas_f_bulk

BATCH_SIZE = 10

device_log_count = 0
http_log_count = 0
logon_log_count = 0
all_datas_f_log_count = 0

device_log_buffer = []
http_log_buffer = []
logon_log_buffer = []
all_datas_f_log_buffer = []

def handle_device_log(row: dict):
    global device_log_count
    device_log_count += 1
    device_log_buffer.append(row)

    if(device_log_count == BATCH_SIZE):
        # send to ml model 
        insert_device_log_bulk(device_log_buffer)
        device_log_count = 0
        print("Device logs : Batch reset")
        device_log_buffer.clear()

def handle_http_log(row: dict):
    global http_log_count
    http_log_count += 1
    http_log_buffer.append(row)
    if(http_log_count == BATCH_SIZE):
        # send to ml model
        insert_http_log_bulk(http_log_buffer)
        http_log_count = 0
        print("Http logs : Batch reset")
        http_log_buffer.clear()

def handle_logon_log(row: dict):
    global logon_log_count
    logon_log_count += 1
    logon_log_buffer.append(row)
    if(logon_log_count == BATCH_SIZE):
        # send to ml model
        insert_logon_log_bulk(logon_log_buffer)
        logon_log_count = 0
        print("Logon logs : Batch reset")
        logon_log_buffer.clear()

def handle_all_datas_f_log(row: dict):
    global all_datas_f_log_count
    all_datas_f_log_count += 1
    all_datas_f_log_buffer.append(row)
    if(all_datas_f_log_count == BATCH_SIZE):
        # send to ml model
        insert_all_datas_f_bulk(all_datas_f_log_buffer)
        all_datas_f_log_count = 0
        print("All Datas F logs : Batch reset")
        all_datas_f_log_buffer.clear()
