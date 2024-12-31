import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
from PyQt6.QtCore import QObject,pyqtSignal
from app.models.user_manager import UserManager
from aiohttp import ClientSSLError
from aiohttp.client_reqrep import ConnectionKey
import logging

logger = logging.getLogger(__name__)

class EventManager(QObject):
    handle_login_event = pyqtSignal(dict)
    set_secret_key = pyqtSignal(str, str)
    handle_refresh_token_event = pyqtSignal(dict)
    logout_get_token_event = pyqtSignal()
    handle_logout_event = pyqtSignal(dict)
    handle_exception_event = pyqtSignal(Exception,str,dict,str)
    
    def __del__(self):
        print("EventManager has been deleted")

class TestUserManager(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up the TestUserManager test case by initializing mock objects and connecting event signals."""
        logger.info("Setting up TestUserManager test case.")
        self.user_manager = UserManager()
        self.user_manager._token_manager = MagicMock()
        self.user_manager.addEvent = MagicMock()
        self.user_manager._error_manager = MagicMock()
        
        self.login_response_data = {
            "access_token": "jooqrnOrNa0BrNWlg68u9sl6SkdFZg",
            "expires_in": 36000,
            "token_type": "Bearer",
            "scope": "read write",
            "refresh_token": "HNvDQjjsnvDySaK0miwG4lttJEl9yD"
        }

        self.event_manager = EventManager()
    
        self.event_manager.handle_login_event.connect(self.user_manager.login)
        self.event_manager.set_secret_key.connect(self.user_manager.generate_secret_key)
        self.event_manager.handle_refresh_token_event.connect(self.user_manager.refresh_token)
        self.event_manager.logout_get_token_event.connect(self.user_manager.logout_get_token)
        self.event_manager.handle_logout_event.connect(self.user_manager.logout)
        self.event_manager.handle_exception_event.connect(self.user_manager.cqm_process_exception)
        
    async def test_notify_token_refreshed_tokens_exists(self):
        """Test the notify_token_refreshed method when tokens already exist."""
        logger.info("Started: test_notify_token_refreshed_tokens_exists")

        data = {"access_token":[{"token":"testAccessToken"}]}
        self.user_manager._token_manager.get_all_tokens = AsyncMock(return_value=data)

        await UserManager.notify_token_refreshed()
        
        self.user_manager.addEvent.emit.assert_called_once_with(
            1, "refresh_token", data, self.user_manager.__class__.__name__
        )
        
        self.user_manager._token_manager.stop_refresh_timer.assert_called_once()
        
        logger.info("Test passed: test_notify_token_refreshed_tokens_exists")
        
    async def test_notify_token_refreshed_tokens_not_exists(self):
        """Test the notify_token_refreshed method when tokens already not exist."""
        logger.info("Started: test_notify_token_refreshed_tokens_not_exists")
        self.user_manager._token_manager.get_all_tokens = AsyncMock(return_value=None)

        await UserManager.notify_token_refreshed()
        
        self.user_manager._token_manager.stop_refresh_timer.assert_called_once()
        self.user_manager._error_manager.emit_critical_error.assert_called_once_with('No valid tokens the application will be closed')

        logger.info("Test Passed: test_notify_token_refreshed_tokens_not_exists")
        
    async def test_generate_secret_key_successful(self):
        """Test that generate_secret_key emits the correct secret key signal successfully."""
        logger.info("Started: test_generate_secret_key_successful")
        self.event_manager.set_secret_key.emit('123456', 'password123')
        
        self.user_manager._token_manager.generate_secret_key.assert_called_once_with('123456', 'password123')
        
        logger.info("Test passed: test_generate_secret_key_successful")
        
    async def test_generate_secret_key_value_error(self):
        """Test generate_secret_key handles ValueError correctly when input is invalid."""
        logger.info("Started: test_generate_secret_key_value_error")
        self.user_manager._token_manager.generate_secret_key = MagicMock(side_effect= ValueError("2FA code cannot be empty and must be a non-empty string."))
        
        self.event_manager.set_secret_key.emit('', 'password123')

        self.event_manager.set_secret_key.emit('abcdef', 'password123')
        
        self.event_manager.set_secret_key.emit('123456', 'password123')

        expected_calls = [
            unittest.mock.call('Validation failed in UserManager: 2FA code must consist of exactly 6 digits.'),
            unittest.mock.call('Validation failed in UserManager: 2FA code must consist of exactly 6 digits.'),
            unittest.mock.call('Validation failed in UserManager: 2FA code cannot be empty and must be a non-empty string.')
        ]
        
        self.user_manager._error_manager.emit_error.assert_has_calls(expected_calls)
        self.assertEqual(self.user_manager._error_manager.emit_error.call_count, 3)
        
        logger.info("test passed: test_generate_secret_key_value_error")
        
    async def test_login_successful(self):
        """Test successful login emits the correct signal and saves the token."""
        logger.info("Started: test_login_successful")
        self.user_manager._token_manager.save_token = AsyncMock()
        
        self.login_response_data["status"] = 200
        self.event_manager.handle_login_event.emit(self.login_response_data)
      
        await asyncio.sleep(0.5)
        self.user_manager._token_manager.save_token.assert_called_once_with(self.login_response_data)
        self.user_manager._token_manager.start_refresh_timer.assert_called_once_with(27040)
        
        self.user_manager.addEvent.emit.assert_called_once_with(
            0, "login_success", {}, self.user_manager.__class__.__name__
        )
        
        logger.info("Test passed: test_login_successful")
        
    async def test_login_keyError(self):
        """Test login handles KeyError when token data is invalid."""
        logger.info("Started: test_login_keyError")
        
        self.user_manager._token_manager.save_token = AsyncMock(side_effect=KeyError("Invalid token data format."))
        
        self.login_response_data["status"] = 200
        self.event_manager.handle_login_event.emit(self.login_response_data)
      
        await asyncio.sleep(0.2)
        self.user_manager._token_manager.save_token.assert_called_once()
        self.user_manager._token_manager.start_refresh_timer.assert_not_called()
        self.user_manager._token_manager.clear_secret_key.assert_called_once()
        self.user_manager._token_manager.clear_tokens.assert_called_once()
        
        self.user_manager._error_manager.emit_critical_error.assert_called_once_with("Applications have faced a critical issue:'Invalid token data format.',Please contact the administrator")
        
        logger.info("Test passed: test_login_keyError")
        
    async def test_login_failed(self):
        """test login failed when it receives login failure signal"""
        logger.info("Started: test_login_failed")
        self.user_manager._token_manager.save_token = AsyncMock()
        
        data = {"status":401, "error":"Unauthorized connection" }
        self.event_manager.handle_login_event.emit(data)
        
        await asyncio.sleep(0.2)
        
        self.user_manager._token_manager.clear_secret_key.assert_called_once()
        self.user_manager.addEvent.emit.assert_called_once_with(0,"login_failed",{"error":data["error"]},self.user_manager.__class__.__name__) 
        
        logger.info("Test passed: test_login_failed")
        
    async def test_login_exception(self):
        """Test login processing exception when it gets it in even"""
        logger.info("Started: test_login_exception")
        self.user_manager._token_manager.save_token = AsyncMock()
        
        connection_key = ConnectionKey(
                        host="example.com", port=443, is_ssl=True, ssl=None, proxy=None, proxy_auth=None,
                        proxy_headers_hash=None
        )

        error = ClientSSLError(
            connection_key=connection_key,
            os_error=OSError("SSL certificate verification failed")
        )
        
        data = {"exception":str(error) }
        self.event_manager.handle_login_event.emit(data)
        
        await asyncio.sleep(0.2)
        
        self.user_manager._token_manager.clear_secret_key.assert_called_once()
        self.user_manager._error_manager.emit_critical_error.assert_called_once_with(f"Applications have faced a critical issue:{data["exception"]},Please contact the administrator")
        
        logger.info("Test passed: test_login_exception")
        
    async def test_refresh_token_successful(self):
        """test refresh token after receiving a signal token will be saved and start a timer"""
        logger.info("Started: test_refresh_token_successful")
        self.user_manager._token_manager.clear_tokens = AsyncMock()
        self.user_manager._token_manager.save_token = AsyncMock()
        
        self.login_response_data["status"] = 200
        self.event_manager.handle_refresh_token_event.emit(self.login_response_data)
      
        await asyncio.sleep(0.2)
        self.user_manager._token_manager.save_token.assert_called_once_with(self.login_response_data)
        self.user_manager._token_manager.start_refresh_timer.assert_called_once_with(27040)
        self.user_manager._error_manager.reset_exception.assert_called_once()
        
        logger.info("test passed: test_refresh_token_successful")
        
    async def test_refresh_token_keyError(self):
        """Test KeyError handler during saving token """
        logger.info("Started: test_refresh_token_keyError")
        
        self.user_manager._token_manager.clear_tokens = AsyncMock()
        self.user_manager._token_manager.save_token = AsyncMock(side_effect=KeyError("Invalid token data format."))
        
        self.login_response_data["status"] = 200
        self.event_manager.handle_refresh_token_event.emit(self.login_response_data)
      
        await asyncio.sleep(0.2)
        self.user_manager._error_manager.emit_critical_error.assert_called_once_with("Applications have faced a critical issue:'Invalid token data format.',Please contact the administrator")
        logger.info("Test passed: test_refresh_token_keyError")
        
    async def test_refresh_token_failed(self):
        """test refresh failed when it receives refresh token failure signal"""
        logger.info("Started: test_refresh_token_failed")
        
        self.user_manager._token_manager.clear_tokens = AsyncMock()
        self.user_manager._token_manager.save_token = AsyncMock()
        
        data = {"status":401, "error":"Unauthorized connection" }
        self.event_manager.handle_refresh_token_event.emit(data)
      
        await asyncio.sleep(0.2)
        self.user_manager._token_manager.stop_refresh_timer.assert_called_once()
        self.user_manager._token_manager.clear_tokens.assert_called_once()
        self.user_manager._token_manager.clear_secret_key.assert_called_once()
        self.user_manager._error_manager.emit_error.assert_called_once_with(f"Session server replied with not correct status:{data["status"]}")

        self.user_manager.addEvent.emit.assert_called_once_with(0,"logout_success",{},self.user_manager.__class__.__name__)
        logger.info("Test passed: test_refresh_token_failed")
        
    async def test_refresh_token_failed_exception(self):
        """Test refresh processing exception when it gets it in even"""
        logger.info("Started: test_refresh_token_failed_exception")
        
        self.user_manager._token_manager.clear_tokens = AsyncMock(side_effect=KeyError("Invalid token data format."))
        self.user_manager._token_manager.save_token = AsyncMock()
        
        data = {"status":401, "error":"Unauthorized connection" }
        self.event_manager.handle_refresh_token_event.emit(data)
      
        await asyncio.sleep(0.2)
        self.user_manager._token_manager.stop_refresh_timer.assert_called_once()

        self.user_manager._error_manager.emit_critical_error.assert_called_once_with("Applications have faced a critical issue:'Invalid token data format.',Please contact the administrator")

        logger.info("Test passed: test_refresh_token_failed_exception")
        
    async def test_logout_get_token(self):
        """Test signal logout_get_token_event whether it will send the right event"""
        logger.info("Started: test_logout_get_token")
        self.user_manager._token_manager.get_token_access_token =  AsyncMock(return_value=MagicMock(token="mock_token"))
 
        self.event_manager.logout_get_token_event.emit()
        
        await asyncio.sleep(0.2)
        
        self.user_manager.addEvent.emit.assert_called_once_with(0,"send_logout",{"access_token":"mock_token"},self.user_manager.__class__.__name__)
        logger.info("Test passed: test_logout_get_token")

    async def test_logout_get_token_error(self):
        """Test ValueError handler during get logout event """
        logger.info("Started: test_logout_get_token_error")
        self.user_manager._token_manager.get_token_access_token =  AsyncMock(side_effect=ValueError("Invalid token type requested."))
 
        self.event_manager.logout_get_token_event.emit()
        
        await asyncio.sleep(0.2)
        
        self.user_manager._error_manager.emit_critical_error.assert_called_once_with('Applications have faced a critical issue:Invalid token type requested.,Please contact the administrator')
        
        logger.info("Test passed: test_logout_get_token_error")
        

    async def test_logout_successful(self):
        """Test successful logout emits the correct signal and clear the tokens."""
        logger.info("Started: test_logout_successful")
        
        self.user_manager._token_manager.clear_tokens = AsyncMock()
        self.user_manager._token_manager.save_token = AsyncMock()
        
        data = {"status" : 200}
        self.event_manager.handle_logout_event.emit(data)
      
        await asyncio.sleep(0.2)
        self.user_manager._token_manager.clear_tokens.assert_called_once()
        self.user_manager._token_manager.stop_refresh_timer.assert_called_once()
        self.user_manager._token_manager.clear_secret_key.assert_called_once()
        
        self.user_manager.addEvent.emit.assert_called_once_with(0,"logout_success",{},self.user_manager.__class__.__name__)
        logger.info("Test passed: test_logout_successful")
        
    async def test_logout_error(self):
        """Test ValueError handler during logout  """
        logger.info("Started: test_logout_error")
        self.user_manager._token_manager.clear_tokens = AsyncMock(side_effect=ValueError("Invalid token type requested."))
        self.user_manager._token_manager.save_token = AsyncMock()
        
        data = {"status" : 200}
        self.event_manager.handle_logout_event.emit(data)
      
        await asyncio.sleep(0.2)
        
        self.user_manager._token_manager.stop_refresh_timer.assert_called_once()
     
        self.user_manager._error_manager.emit_critical_error.assert_called_once_with('Applications have faced a critical issue:Invalid token type requested.,Please contact the administrator')
        logger.info("Test passed: test_logout_error")

    async def test_logout_failed(self):
        """test logout failed when it receives logout failure signal"""
        logger.info("Started: test_logout_failed")
        self.user_manager._token_manager.clear_tokens = AsyncMock()
        self.user_manager._token_manager.save_token = AsyncMock()
        
        data = {"status" : 401, "error":"Unauthorized connection"}
        self.event_manager.handle_logout_event.emit(data)
      
        await asyncio.sleep(0.2)
        
        self.user_manager._token_manager.clear_tokens.assert_not_called()
        self.user_manager._token_manager.stop_refresh_timer.assert_not_called()
        self.user_manager._token_manager.clear_secret_key.assert_not_called()
        
        self.user_manager._error_manager.emit_critical_error.assert_called_once_with('Applications have faced a critical issue:Unauthorized connection,Please contact the administrator')
        logger.info("Test passed: test_logout_failed")