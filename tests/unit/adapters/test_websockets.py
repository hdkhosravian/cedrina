import pytest
import sys
import os
from unittest.mock import patch, AsyncMock, MagicMock

# Adjust sys.path to include src directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from adapters.websockets import websocket_health

@pytest.mark.asyncio
async def test_websocket_health_default_language(mocker):
    """Test WebSocket health endpoint with default language."""
    websocket = MagicMock()
    websocket.query_params = {'lang': 'en'}
    websocket.accept = AsyncMock()
    websocket.send_json = AsyncMock()
    websocket.close = AsyncMock()
    
    mocker.patch('utils.i18n.get_translated_message', return_value='System is operational')
    mocker.patch('core.logging.logger.debug', new_callable=AsyncMock)
    
    await websocket_health(websocket)
    
    websocket.accept.assert_awaited_once()
    websocket.send_json.assert_awaited_once_with({'status': 'connected', 'message': 'System is operational'})
    websocket.close.assert_awaited_once()
    
    from core.logging import logger
    logger.debug.assert_called_once_with('websocket_health_connected')

@pytest.mark.asyncio
async def test_websocket_health_specific_language(mocker):
    """Test WebSocket health endpoint with a specific language parameter."""
    websocket = MagicMock()
    websocket.query_params = {'lang': 'pt'}
    websocket.accept = AsyncMock()
    websocket.send_json = AsyncMock()
    websocket.close = AsyncMock()
    
    mocker.patch('adapters.websockets.get_translated_message', return_value='Sistema está operacional')
    mocker.patch('core.logging.logger.debug', new_callable=AsyncMock)
    
    await websocket_health(websocket)
    
    websocket.accept.assert_awaited_once()
    websocket.send_json.assert_awaited_once_with({'status': 'connected', 'message': 'Sistema está operacional'})
    websocket.close.assert_awaited_once()
    
    from core.logging import logger
    logger.debug.assert_called_once_with('websocket_health_connected')

@pytest.mark.asyncio
async def test_websocket_health_no_language_param(mocker):
    """Test WebSocket health endpoint without a language parameter."""
    websocket = MagicMock()
    websocket.query_params = {}
    websocket.accept = AsyncMock()
    websocket.send_json = AsyncMock()
    websocket.close = AsyncMock()
    
    mocker.patch('utils.i18n.get_translated_message', return_value='System is operational')
    mocker.patch('core.logging.logger.debug', new_callable=AsyncMock)
    
    await websocket_health(websocket)
    
    websocket.accept.assert_awaited_once()
    websocket.send_json.assert_awaited_once_with({'status': 'connected', 'message': 'System is operational'})
    websocket.close.assert_awaited_once()
    
    from core.logging import logger
    logger.debug.assert_called_once_with('websocket_health_connected') 