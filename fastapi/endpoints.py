from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from sqlite_functions import create_tables
from log_handlers import handle_device_log, handle_http_log, handle_logon_log, handle_all_datas_f_log, handle_netflow_day_02_log, handle_wls_day_02_log

app = FastAPI()

# API endpoints
@app.on_event("startup")
async def startup_event():
    create_tables()

@app.get("/")
async def root():
    return {"message": "Log Service is running"}

@app.post("/log/ingest/")
async def ingest_log(payload: dict):  
    print(payload)
    try:

        logtype = payload.get("logtype")


        # Handle different log types explicitly
        if logtype == "device":
            handle_device_log(payload)
        elif logtype == "http":
            handle_http_log(payload)
        elif logtype == "logon":
            handle_logon_log(payload)
        elif logtype == "all_datas_f":
            handle_all_datas_f_log(payload)
        elif logtype == "netflow_day-02":
            handle_netflow_day_02_log(payload)
        elif logtype == "wls_day-02":
            handle_wls_day_02_log(payload)

        else:
            raise HTTPException(status_code=400, detail=f"Invalid logtype '{logtype}'")

        return JSONResponse({
            "status": "success",
            "logtype": logtype,
            "log": "empty for now"
        })

    except HTTPException as http_err:
        raise http_err  # Let FastAPI handle HTTP exceptions properly
    except Exception as e:
        return JSONResponse(
            {"status": "error", "detail": str(e)},
            status_code=500
        )
    
