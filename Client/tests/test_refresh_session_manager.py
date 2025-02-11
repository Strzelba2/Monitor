import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
import logging

from app.managers.refresh_session import RefreshSessionManager

logger = logging.getLogger(__name__)

class TestRefreshSessionManager(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.manager = RefreshSessionManager()
        
    def test_initialization(self):
        """Test that the manager is initialized with correct default values."""
        logger.info("Started: test_initialization")
        self.assertIsNone(self.manager.refresh_interval)
        self.assertFalse(self.manager.is_running)
        self.assertIsNone(self.manager._task)
        self.assertIsInstance(self.manager.event_loop, asyncio.AbstractEventLoop)
        
        logger.info("Test passed: test_initialization")
        
    async def test_start_valid(self):
        """Test starting the manager with a valid interval."""
        logger.info("Started: test_start_valid")
        interval = 100
        self.manager.start(refresh_interval=interval)

        self.assertTrue(self.manager.is_running)
        self.assertEqual(self.manager.refresh_interval, interval)
        self.assertIsNotNone(self.manager._task)
        logger.info("Test passed: test_start_valid")
        
    async def test_start_while_running(self):
        """Test that starting while already running raises an error."""
        logger.info("Started: test_start_while_running")
        self.manager.is_running = True
        self.manager._task = MagicMock(done=MagicMock(return_value=False))

        with self.assertRaises(RuntimeError) as context:
            self.manager.start(refresh_interval=100)

        self.assertEqual(str(context.exception), "A token refresh task is already active. Please stop it before starting a new one.")
        logger.info("Test passed: test_start_while_running")
        
        
    async def test_refresh_session_coroutine(self):
        """Test the behavior of the _refresh_session coroutine."""
        logger.info("Started: test_refresh_session_coroutine")
        
        with patch("app.managers.user_manager.UserManager.notify_session_refreshed") as user_manager_mock:
            self.manager.start(refresh_interval=0.2)
            
            await asyncio.sleep(1)
            
            self.assertEqual(user_manager_mock.call_count,4)
            
        logger.info("Test passed: test_refresh_session_coroutine")
        
    async def test_refresh_session_coroutine_cancel(self):
        """Test the behavior of the _refresh_session coroutine canceled."""
        logger.info("Started: test_refresh_session_coroutine_cancel")
        with patch("app.managers.user_manager.UserManager.notify_session_refreshed") as user_manager_mock:
            self.manager.start(refresh_interval=0.2)
            
            await asyncio.sleep(0.3)
            self.manager._task.cancel()
            await asyncio.sleep(0.2)
            
            self.assertEqual(user_manager_mock.call_count,1)
            
        logger.info("Test passed: test_refresh_session_coroutine_cancel")
        
    async def test_stop_valid(self):
        """Test stopping the manager when a task is running."""
        logger.info("Started: test_stop_valid")
        with patch("app.managers.user_manager.UserManager.notify_session_refreshed") as user_manager_mock:
            self.manager.start(refresh_interval=0.2)
            
            await asyncio.sleep(0.3)
            await self.manager.stop()

            self.assertEqual(user_manager_mock.call_count,1)
            self.assertFalse(self.manager.is_running)
            self.assertIsNone(self.manager._task)
            
        logger.info("Test passed: test_stop_valid")
        