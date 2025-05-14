from fastapi import APIRouter, WebSocket
from src.core.logging import logger
from src.utils.i18n import get_translated_message

ws_router = APIRouter()

@ws_router.websocket("/health")
async def websocket_health(websocket: WebSocket):
    await websocket.accept()
    lang = websocket.query_params.get("lang", "en")
    status_message = get_translated_message("health_status_ok", lang)
    logger.debug("websocket_health_connected")
    await websocket.send_json({"status": "connected", "message": status_message})
    await websocket.close()