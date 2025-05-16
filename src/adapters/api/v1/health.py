from fastapi import APIRouter, Request
from src.core.config.settings import settings
from src.core.logging import logger
from src.utils.i18n import get_translated_message

router = APIRouter()

@router.get("/health", response_model=dict)
async def health_check(request: Request):
    language = request.state.language
    status_message = get_translated_message("health_status_ok", language)
    return {"status": "ok", "env": settings.APP_ENV, "message": status_message}