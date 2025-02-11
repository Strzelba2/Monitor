import unittest
from unittest.mock import AsyncMock, MagicMock
from app.exceptions.connection_exc import UnauthorizedConnectionError
from app.managers.stream_manager import StreamManager
import asyncio
import logging

logger = logging.getLogger(__name__)

class AsyncIterator:
    def __init__(self, seq):
        self.iter = iter(seq)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self.iter)
        except StopIteration:
            raise StopAsyncIteration


class TestStreamManagerModel(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        """Set up a StreamManager instance and mock dependencies."""
        self.stream_manager = StreamManager()
        self.stream_manager.server_client = MagicMock()
        self.stream_manager.addEvent = MagicMock()
        
    async def async_generator(self, items):
        """ Helper function to create an async generator for mocking `send_stream_request`. """
        for item in items:
            yield item
            await asyncio.sleep(0)
        
        
    def test_logout_session(self):
        """Test logout_session method to ensure it stops the stream and emits an event."""
        logger.info("Started: test_logout_session")
        self.stream_manager.stop_stream = MagicMock()
        
        self.stream_manager.logout_session()
        
        self.stream_manager.stop_stream.assert_called_once()
        self.stream_manager.addEvent.emit.assert_called_once_with(
            2, "request_with_token", {"event": "logout_session", "data": {}}, "StreamManager"
        )
        
        logger.info("Test Passed: test_logout_session")

    async def test_start_stream(self):
        """Test _start_stream method to ensure it starts the stream and processes frames."""
        logger.info("Started: test_start_stream")
        
        self.stream_manager.server_client.send_stream_request = MagicMock(
            return_value=self.async_generator([b'\xff\xd8image_data'])
        )
        
        self.stream_manager.process_frame = MagicMock()
        
        await self.stream_manager._start_stream("session123", "hmac_token")
        
        self.stream_manager.server_client.send_stream_request.assert_called_once()
        self.stream_manager.process_frame.assert_called_once()
        
        logger.info("Test Passed: test_start_stream")
        
    async def test_close_session(self):
        """Test _close_session to ensure it stops the stream and closes session."""
        logger.info("Started: test_close_session")
        self.stream_manager.server_client.running = True
        self.stream_manager.server_client.close_session = AsyncMock()
        self.stream_manager.stop_stream = MagicMock()
        
        await self.stream_manager._close_session()
        
        self.stream_manager.stop_stream.assert_called_once()
        self.stream_manager.server_client.close_session.assert_awaited_once()
        
        logger.info("Test Passed: test_close_session")
        
    def test_change_image_size(self):
        """Test change_image_size method updates width and height correctly."""
        logger.info("Started: test_change_image_size")
        self.stream_manager.change_image_size(1920, 1080)
        
        self.assertEqual(self.stream_manager.width, 1920)
        self.assertEqual(self.stream_manager.height, 1080)
        
        logger.info("Test passed: test_change_image_size")
        
    async def test_handle_stream_success(self):
        """Test handle_stream when session credentials are valid."""
        logger.info("Started: test_handle_stream_success")
        
        self.stream_manager._start_stream = AsyncMock()
        kwargs = {"status": 200, "token": "test_token", "session_id": "session123"}
        
        await self.stream_manager.handle_stream(kwargs)
        
        self.stream_manager._start_stream.assert_awaited_once_with("session123", "test_token")
        
        logger.info("Test started: test_handle_stream_success")
        
    async def test_handle_stream_failure(self):
        """Test handle_stream when authorization fails."""
        logger.info("Started: test_handle_stream_failure")
        
        self.stream_manager.logout_session = MagicMock()
        kwargs = {"status": 403}
        
        await self.stream_manager.handle_stream(kwargs)
        
        self.stream_manager.logout_session.assert_called_once()
        
        logger.info("Test Passed: test_handle_stream_failure")
        
    async def test_handle_stream_Exception(self):
        """Test handle_stream when authorization fails."""
        logger.info("Started: test_handle_stream_Exception")
        self.stream_manager.logout_session = MagicMock()
        self.stream_manager.server_client.send_stream_request = MagicMock(
            side_effect=UnauthorizedConnectionError("UnauthorizedConnection"))

        kwargs = {"status": 200, "token": "test_token", "session_id": "session123"}
        
        await self.stream_manager.handle_stream(kwargs)
        
        self.stream_manager.logout_session.assert_called_once()
        
        logger.info("Test Passed: test_handle_stream_Exception")
        
    def test_stop_stream(self):
        """Test stop_stream method resets parameters and stops the client."""
        logger.info("Started: test_stop_stream")
        
        self.stream_manager.server_client.running = True
        self.stream_manager.width = 1920
        self.stream_manager.height = 1080
        
        self.stream_manager.stop_stream()
        
        self.assertFalse(self.stream_manager.server_client.running)
        self.assertIsNone(self.stream_manager.width)
        self.assertIsNone(self.stream_manager.height)
        
        logger.info("Test Passed: test_stop_stream")