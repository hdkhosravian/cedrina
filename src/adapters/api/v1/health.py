from fastapi import APIRouter, Request
from src.core.config.settings import settings
from src.core.logging import logger
from src.utils.i18n import get_translated_message

router = APIRouter()

@router.get("/health", response_model=dict)
async def health_check(request: Request):
    language = request.state.language
    logger.debug("health_check_called", language=language)
    status_message = get_translated_message("health_status_ok", language)
    logger.debug("health_check_response", status_message=status_message)
    return {"status": "ok", "env": settings.APP_ENV, "message": status_message}