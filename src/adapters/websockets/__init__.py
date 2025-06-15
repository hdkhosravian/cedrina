from core.logging import logger
from utils.i18n import get_translated_message
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

ws_router = APIRouter()

@ws_router.websocket("/health")
async def websocket_health(websocket: WebSocket):
    await websocket.accept()
    lang = websocket.query_params.get("lang", "en")
    status_message = get_translated_message("health_status_ok", lang)
    await logger.debug("websocket_health_connected")
    await websocket.send_json({"status": "connected", "message": status_message})
    await websocket.close()