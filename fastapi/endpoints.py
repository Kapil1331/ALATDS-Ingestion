from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from sqlite_functions import create_tables
from log_handlers import handle_device_log, handle_http_log, handle_logon_log 

app = FastAPI()

# Functions

# API endpoints
@app.on_event("startup")
async def startup_event():
    create_tables()

@app.get("/")
async def root():
    return {"message": "Log Service is running"}

@app.post("/log/ingest/{logtype}")
async def ingest_log(logtype: str, payload: dict):
    try:
        row = payload.get("row")
        if not row:
            raise HTTPException(status_code=400, detail="Missing 'row' in request body")

        # Handle different log types explicitly
        if logtype == "device":
            handle_device_log(row)
        elif logtype == "http":
            handle_http_log(row)
        elif logtype == "logon":
            handle_logon_log(row)
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
    
