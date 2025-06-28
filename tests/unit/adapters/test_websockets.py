import os
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

# Adjust sys.path to include src directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src")))

from adapters.websockets import websocket_health
from src.core.config.settings import settings
from src.utils.i18n import get_translated_message


@pytest.mark.asyncio
async def test_websocket_health_default_language(mocker):
    """Test WebSocket health endpoint with default language."""
    websocket = MagicMock()
    websocket.query_params = {"lang": "en"}
    websocket.accept = AsyncMock()
    websocket.send_json = AsyncMock()
    websocket.close = AsyncMock()

    expected_message = get_translated_message("health_status_ok", "en")
    mocker.patch("src.utils.i18n.get_translated_message", return_value=expected_message)
    mocker.patch("src.core.logging.logger.debug", new_callable=MagicMock)

    await websocket_health(websocket)

    websocket.accept.assert_awaited_once()
    websocket.send_json.assert_awaited_once_with(
        {"status": "connected", "message": expected_message}
    )
    websocket.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_websocket_health_farsi(mocker):
    """Test WebSocket health endpoint with Farsi language."""
    websocket = MagicMock()
    websocket.query_params = {"lang": "fa"}
    websocket.accept = AsyncMock()
    websocket.send_json = AsyncMock()
    websocket.close = AsyncMock()

    expected_message = get_translated_message("health_status_ok", "fa")
    mocker.patch("src.utils.i18n.get_translated_message", return_value=expected_message)
    mocker.patch("src.core.logging.logger.debug", new_callable=MagicMock)

    await websocket_health(websocket)

    websocket.accept.assert_awaited_once()
    websocket.send_json.assert_awaited_once_with(
        {"status": "connected", "message": expected_message}
    )
    websocket.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_websocket_health_arabic(mocker):
    """Test WebSocket health endpoint with Arabic language."""
    websocket = MagicMock()
    websocket.query_params = {"lang": "ar"}
    websocket.accept = AsyncMock()
    websocket.send_json = AsyncMock()
    websocket.close = AsyncMock()

    expected_message = get_translated_message("health_status_ok", "ar")
    mocker.patch("src.utils.i18n.get_translated_message", return_value=expected_message)
    mocker.patch("src.core.logging.logger.debug", new_callable=MagicMock)

    await websocket_health(websocket)

    websocket.accept.assert_awaited_once()
    websocket.send_json.assert_awaited_once_with(
        {"status": "connected", "message": expected_message}
    )
    websocket.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_websocket_health_no_language_param(mocker):
    """Test WebSocket health endpoint without a language parameter."""
    websocket = MagicMock()
    websocket.query_params = {}
    websocket.accept = AsyncMock()
    websocket.send_json = AsyncMock()
    websocket.close = AsyncMock()

    expected_message = get_translated_message("health_status_ok", settings.DEFAULT_LANGUAGE)
    mocker.patch("src.utils.i18n.get_translated_message", return_value=expected_message)
    mocker.patch("src.core.logging.logger.debug", new_callable=MagicMock)

    await websocket_health(websocket)

    websocket.accept.assert_awaited_once()
    websocket.send_json.assert_awaited_once_with(
        {"status": "connected", "message": expected_message}
    )
    websocket.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_websocket_health_invalid_language(mocker):
    """Test WebSocket health endpoint with invalid language falls back to default."""
    websocket = MagicMock()
    websocket.query_params = {"lang": "invalid"}
    websocket.accept = AsyncMock()
    websocket.send_json = AsyncMock()
    websocket.close = AsyncMock()

    expected_message = get_translated_message("health_status_ok", settings.DEFAULT_LANGUAGE)
    mocker.patch("src.utils.i18n.get_translated_message", return_value=expected_message)
    mocker.patch("src.core.logging.logger.debug", new_callable=MagicMock)

    await websocket_health(websocket)

    websocket.accept.assert_awaited_once()
    websocket.send_json.assert_awaited_once_with(
        {"status": "connected", "message": expected_message}
    )
    websocket.close.assert_awaited_once()
