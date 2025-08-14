import streamlit as st
import asyncio
import websockets

async def fetch_logs():
    uri = "ws://localhost:8000/ws/logs"
    logs = []
    try:
        async with websockets.connect(uri) as websocket:
            # Only fetch a small batch each time to avoid blocking
            for _ in range(5):
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=1)
                    logs.append(message)
                except asyncio.TimeoutError:
                    break
    except Exception as e:
        st.error(f"WebSocket connection failed: {e}")
    return logs

def terminal_component():
    st.subheader("📟 Live Log Terminal")
    if "terminal_logs" not in st.session_state:
        st.session_state.terminal_logs = []

    new_logs = asyncio.run(fetch_logs())
    if new_logs:
        st.session_state.terminal_logs.extend(new_logs)

    st.code("\n".join(st.session_state.terminal_logs[-20:]), language="json")
