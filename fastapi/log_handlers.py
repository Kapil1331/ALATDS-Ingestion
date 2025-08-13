from sqlite_functions import insert_device_log, insert_http_log, insert_logon_log
from sqlite_functions import insert_device_log_bulk, insert_http_log_bulk, insert_logon_log_bulk, insert_all_datas_f_bulk, insert_netflow_day_02_bulk, insert_wls_day_02_bulk
from sqlite_functions import insert_wsl_predictions_bulk

from ML.emp_data_classification.emp_data_analyzer import emp_data_classifier
from ML.wsl_classification.wsl_classifier import wsl_classifier
import time
import pandas as pd

BATCH_SIZE = 10

device_log_count = 0
http_log_count = 0
logon_log_count = 0
all_datas_f_log_count = 0
netflow_day_02_log_count = 0
wls_day_02_log_count = 0

device_log_buffer = []
http_log_buffer = []
logon_log_buffer = []
all_datas_f_log_buffer = []
netflow_day_02_log_buffer = []
wls_day_02_log_buffer = []

total_all_datas_f_log_count = 0
model_all_datas_f_log_buffer = []


emp_data_classifier = emp_data_classifier()
wsl_classifier = wsl_classifier()
if wsl_classifier.model is None:
    wsl_classifier.train()
        
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
    global total_all_datas_f_log_count
    all_datas_f_log_count += 1
    all_datas_f_log_buffer.append(row)
    total_all_datas_f_log_count += 1

    model_row = {
        "log_type": "all_datas_f",
        "log_id": total_all_datas_f_log_count,
        "path": row.get("path", ""),
        "body": row.get("body", "")
    }
    model_all_datas_f_log_buffer.append(model_row)
    
    if(all_datas_f_log_count == BATCH_SIZE):
        try:
            # send to ml model
            print(pd.DataFrame(model_all_datas_f_log_buffer))
            print("going to predic in some time !!!!!!!!!!")
            results = wsl_classifier.predict(pd.DataFrame(model_all_datas_f_log_buffer))
            print("sending the predictions !!!!!!!!!!")
            print(results)
            
            # Insert predictions first
            insert_wsl_predictions_bulk(results.to_dict(orient='records'))
            
            # If predictions successful, insert the original logs
            insert_all_datas_f_bulk(all_datas_f_log_buffer)
            
            all_datas_f_log_count = 0
            print("All Datas F logs : Batch reset")
            all_datas_f_log_buffer.clear()
            model_all_datas_f_log_buffer.clear()
        except Exception as e:
            print(f"Error processing batch: {str(e)}")
            raise





def handle_netflow_day_02_log(row: dict):
    global netflow_day_02_log_count
    netflow_day_02_log_count += 1
    netflow_day_02_log_buffer.append(row)
    if(netflow_day_02_log_count == BATCH_SIZE):
        # send to ml model
        insert_netflow_day_02_bulk(netflow_day_02_log_buffer)
        netflow_day_02_log_count = 0
        print("Netflow Day 02 logs : Batch reset")
        netflow_day_02_log_buffer.clear()


def handle_wls_day_02_log(row: dict):
    global wls_day_02_log_count
    wls_day_02_log_count += 1
    wls_day_02_log_buffer.append(row)
    if(wls_day_02_log_count == BATCH_SIZE):
        # send to ml model
        insert_wls_day_02_bulk(wls_day_02_log_buffer)
        wls_day_02_log_count = 0
        print("WLS Day 02 logs : Batch reset")
        wls_day_02_log_buffer.clear()
