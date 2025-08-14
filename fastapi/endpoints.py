# fastapi_main.py

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from sqlite_functions import create_tables, create_result_tables
from log_handlers import (
    handle_device_log, handle_http_log, handle_logon_log,
    handle_all_datas_f_log, handle_netflow_day_02_log, handle_wls_day_02_log
)

from sqlite_functions import threat_distribution, fetch_results
from fastapi import Query

app = FastAPI()

# --- WebSocket Connection Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

# Startup
@app.on_event("startup")
async def startup_event():
    create_tables()
    create_result_tables()

@app.get("/")
async def root():
    return {"message": "Log Service is running"}

# --- WebSocket endpoint ---
@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # not using incoming messages for now
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- Log Ingest Endpoint ---
@app.post("/log/ingest/")
async def ingest_log(payload: dict):
    try:
        logtype = payload.get("logtype")
        print(payload)  # still logs to terminal

        # Handle different log types
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

        # Broadcast to WebSocket clients
        await manager.broadcast(str(payload))

        return JSONResponse({
            "status": "success",
            "logtype": logtype
        })

    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        return JSONResponse(
            {"status": "error", "detail": str(e)},
            status_code=500
        )


@app.get("/threat_dist")
async def get_threat_distribution(logtype: str = Query(..., description="Log type for threat distribution")):
    try:
        df = threat_distribution(logtype)
        data = df.to_dict(orient="records")  # Convert to list of dicts
        return JSONResponse(content=data)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    

@app.get("/wsl_predictions")
async def get_wsl_predictions():
    try:
        df = fetch_results("wsl_predictions", limit=100)
        data = df.to_dict(orient="records")  # Convert to list of dicts
        return JSONResponse(content=data)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/total_analysis")
async def get_total_analysis():
    try:
        df = fetch_results("sqlite_sequence")
        data = df.to_dict(orient="records")  # Convert to list of dicts
        return JSONResponse(content=data)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/employee_analysis")
async def get_employee_analysis():
    try:
        df = fetch_results("emp_analysis_results", limit=100)
        data = df.to_dict(orient="records")  # Convert to list of dicts
        return JSONResponse(content=data)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})