import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
from PyQt6.QtCore import QObject,pyqtSignal

from app.managers.event_manager import CentralQueueManager

import logging

logger = logging.getLogger(__name__)

class SessionViewModel(QObject):
    addEvent = pyqtSignal(int,str,dict,str)
    
    def __del__(self):
        logger.info("SessionViewModel has been deleted")

class TestCentralQueueManager(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up the test environment."""
        self.manager = CentralQueueManager()
        self.session_view = SessionViewModel()

        self.manager.handle_exception_event = MagicMock()
        self.manager.send_login_event = MagicMock()
        self.manager.send_refresh_token_event = MagicMock()
        self.manager.close_stream_session = MagicMock()
        self.manager.session_update_event = MagicMock()
        
        self.session_view.addEvent.connect(self.manager.add_task)
  
    async def test_add_task(self):
        """Test adding a task to the priority queue."""
        logger.info("Test Started test_add_task")
        
        self.session_view.addEvent.emit(0,"login", {"code": "123", "password": "secret"}, "auth")
        
        await asyncio.sleep(1)

        self.assertEqual(self.manager.tasks.qsize(), 1)
        priority, event_type, payload, module = await self.manager.tasks.get()
        
        await asyncio.sleep(1)
        
        self.assertEqual(priority, 0)
        self.assertEqual(event_type, "login")
        self.assertEqual(payload, {"code": "123", "password": "secret"})
        self.assertEqual(module, "auth")
        
        logger.info("Test Passed test_add_task")
        
    async def test_add_task_with_exception(self):
        """Test adding a task when asyncio.run_coroutine_threadsafe raises an exception."""
        logger.info("Test Started test_add_task_with_exception")
        
        mock_put = AsyncMock(side_effect=RuntimeError("Simulated exception in put"))
        with patch('asyncio.PriorityQueue.put', mock_put):

            self.session_view.addEvent.emit(0,"login", {"code": "123", "password": "secret"}, "auth")
            
            await asyncio.sleep(1)

            self.assertEqual(self.manager.tasks.qsize(), 0)
            mock_put.assert_called_once_with((0, "login", {"code": "123", "password": "secret"}, "auth"))
            
            self.manager.handle_exception_event.emit.assert_called_once_with(
                unittest.mock.ANY, 'login', {'code': '123', 
                'password': 'secret'}, 'auth'
            )
        
        logger.info("Test Passed test_add_task_with_exception")
            
    async def test_emit_event_success(self):
        """Test emitting an event successfully."""
        logger.info("Test Started test_emit_event_success")
        
        self.manager.emit_event = MagicMock()

        try:   
            task =asyncio.create_task(self.manager.start())
            
            await asyncio.sleep(1)
                
            payload = {"code": "123", "password": "secret"}
            self.session_view.addEvent.emit(0,"login", payload, "auth")

            await asyncio.sleep(1)
            
            task.cancel()
            
        except asyncio.CancelledError:
                pass

        self.manager.emit_event.assert_called_once_with("login", {"code": "123", "password": "secret"})
          
        logger.info("Test Passed test_emit_event_success")     
    
    async def test_emit_event_priority_order(self):
        """Test emitting events with different priorities and their processing order."""
        logger.info("Test Started test_emit_event_priority_order")
        
        processed_events = []

        with patch.object(self.manager, "emit_event", side_effect=lambda event_type, payload: processed_events.append((event_type, payload))):
            try:
                task = asyncio.create_task(self.manager.start())

                payload_0 = {"code": "123", "password": "secret_0"}
                payload_1 = {"code": "456", "password": "secret_1"}
                payload_2 = {"code": "789", "password": "secret_2"}
                
                
                self.session_view.addEvent.emit(1, "login", payload_1, "auth")
                self.session_view.addEvent.emit(0, "login", payload_0, "auth")
                self.session_view.addEvent.emit(2, "login", payload_2, "auth")

                await asyncio.sleep(2)

                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            except asyncio.CancelledError:
                pass
        expected_order = [
            ("login", {"code": "123", "password": "secret_0"}),  # Priorytet 0
            ("login", {"code": "456", "password": "secret_1"}),  # Priorytet 1
            ("login", {"code": "789", "password": "secret_2"}),  # Priorytet 2
        ]
        self.assertEqual(processed_events, expected_order) 
        
        logger.info("Test Passed test_emit_event_priority_order")  
        
    async def test_emit_event_error(self):
        """Test emitting events with exception RuntimeError"""
        logger.info("Test Started test_emit_event_error")
        
        with patch.object(self.manager, "emit_event", side_effect=RuntimeError("Simulated exception in emit_event")):
            try:
                task = asyncio.create_task(self.manager.start())

                payload_0 = {"code": "123", "password": "secret_0"}

                self.session_view.addEvent.emit(0, "login", payload_0, "auth")
                await asyncio.sleep(2)

                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            except asyncio.CancelledError:
                pass
            
        self.assertEqual(self.manager.tasks.qsize(), 0)
        
        self.manager.handle_exception_event.emit.assert_called_once_with(
            unittest.mock.ANY, 'login', {'code': '123', 'password': 'secret_0'}, 'auth'
        )
        
        logger.info("Test Passed test_emit_event_error")
        
    async def test_emit_event_clear_tasks(self):
        """Test emitting events with clear tasts function"""
        logger.info("Test Started test_emit_event_clear_tasks")
        try:
            task = asyncio.create_task(self.manager.start())
            payload_0 = {"error":"error during process a login"}
            payload_1 = {"code": "456", "password": "secret_1"}
            payload_2 = {"token": "789"}
            
            
            self.session_view.addEvent.emit(0, "login", payload_1, "auth")
            self.session_view.addEvent.emit(0, "login_failed", payload_0, "auth")
            self.session_view.addEvent.emit(1, "refresh_token", payload_2, "auth")

            await asyncio.sleep(2)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        except asyncio.CancelledError:
            pass
        
        self.manager.send_refresh_token_event.emit.assert_not_called()
        
        logger.info("Test Passed test_emit_event_clear_tasks")
        
    async def test_multiple_events_close_and_update(self):
        """Test emitting events with close and update tasts function"""

        logger.info("Test Started test_multiple_events_close_and_update")

        task = asyncio.create_task(self.manager.start())
        
        async def emit_events():
            self.session_view.addEvent.emit(0, "close_stream_session", {}, type(self).__name__)
            self.session_view.addEvent.emit(0, "session_update", {"available": False}, type(self).__name__)

        await asyncio.ensure_future(emit_events())
        
        await asyncio.sleep(2)
        
        self.manager.close_stream_session.emit.assert_called_once()
        self.manager.session_update_event.emit.assert_called_once()
        
    


            
            