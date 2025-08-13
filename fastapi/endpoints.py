from fastapi import FastAPI, HTTPException, Body, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import Optional
import json
import asyncio

# Import your own functions
from sqlite_functions import create_tables, get_log_src
from log_handlers import handle_device_log, handle_http_log, handle_logon_log

app = FastAPI()

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- Managers ----------------
class AlertManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

# Create managers
manager = ConnectionManager()
alert_manager = AlertManager()

# ---------------- Helper Functions ----------------
async def broadcast_log_update(logtype: str, log_data: dict):
    message = json.dumps({
        "type": "log_update",
        "logtype": logtype,
        "log": log_data,
        "timestamp": datetime.now().isoformat()
    })
    await manager.broadcast(message)


async def trigger_alert(alert_data: dict):
    message = json.dumps({
        "type": "alert",
        "timestamp": datetime.now().isoformat(),
        "data": {
            "severity": alert_data.get("severity", "info"),
            "title": alert_data.get("title", "New Alert"),
            "message": alert_data.get("message", ""),
            "details": alert_data.get("details", None)
        }
    })
    await alert_manager.broadcast(message)


async def trigger_log_update(message: str, sender: Optional[str] = None):
    """Send a log_update event to all connected terminal clients."""
    payload = json.dumps({
        "type": "log_update",  # Matches LogTerminal UI expectation
        "logtype": sender or "system",
        "log": {"message": message},
        "timestamp": datetime.now().isoformat()
    })
    await manager.broadcast(payload)



# ---------------- Startup ----------------
@app.on_event("startup")
async def startup_event():
    create_tables()

# ---------------- API Endpoints ----------------
@app.get("/")
async def root():
    return {"message": "Log Service is running"}

@app.post("/log/ingest/")
async def ingest_log(payload: dict):
    try:
        logtype = payload.get("logtype")
        
        await trigger_log_update(payload, logtype)

        
        if logtype == "device":
            handle_device_log(payload)
        elif logtype == "http":
            handle_http_log(payload)
        elif logtype == "logon":
            handle_logon_log(payload)
        else:
            raise HTTPException(status_code=400, detail=f"Invalid logtype '{logtype}'")

        return JSONResponse({
            "status": "success",
            "logtype": logtype,
            "log": "empty for now"
        })

    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        return JSONResponse({"status": "error", "detail": str(e)}, status_code=500)

@app.get("/log_src")
async def get_threat_src():
    try:
        return JSONResponse(get_log_src())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/demo_alert")
async def demo_alert(
    severity: str = Body(..., example="high"),
    title: str = Body(..., example="System Warning"),
    message: str = Body(..., example="High memory usage detected"),
    memory_usage: int = Body(..., example=90),
    threshold: int = Body(..., example=80)
):
    await trigger_alert({
        "severity": severity,
        "title": title,
        "message": message,
        "details": {"memory_usage": memory_usage, "threshold": threshold}
    })
    return {"status": "test alert sent"}

@app.post("/demo_terminal")
async def demo_terminal(
    message: str = Body(..., example="Hello, terminal clients!"),
    sender: Optional[str] = Body(None, example="System")
):
    await trigger_log_update(message, sender)
    return {"status": "test terminal message sent"}


# ---------------- WebSocket Endpoints ----------------
@app.websocket("/ws/terminal")
async def websocket_terminal(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # Keeps connection alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await alert_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # Keeps connection alive
    except WebSocketDisconnect:
        alert_manager.disconnect(websocket)
