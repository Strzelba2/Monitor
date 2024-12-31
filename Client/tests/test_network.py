import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import ClientSession, ClientTimeout,ClientSSLError
from aiohttp.client_reqrep import ConnectionKey
from app.network.Session_client import SessionClient
from app.database.data_factory import create_tokens
from config.config import Config
from qasync import QEventLoop
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtCore import QTimer
from PyQt6.QtCore import QObject, pyqtSignal
import asyncio
import ssl

import logging

logger = logging.getLogger(__name__)


class EventManager(QObject):
    send_login_event = pyqtSignal(dict)
    send_refresh_token_event = pyqtSignal(dict)
    send_logout_event = pyqtSignal(str)
    
    def __del__(self):
        print("EventManager has been deleted")

class TestSessionClient(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QGuiApplication([])
    
    async def asyncSetUp(self):
        """
        Set up mock objects and a SessionClient instance for testing.
        """
        self.loop = QEventLoop(self.app)
        asyncio.set_event_loop(self.loop)
        
        self.client = SessionClient()
        self.event_manager = EventManager()
        self.client.session = MagicMock(spec=ClientSession)
        self.client.addEvent = MagicMock()
        
        self.event_manager.send_login_event.connect(self.client.send_login_request)
        self.event_manager.send_refresh_token_event.connect(self.client.send_refresh_token_request)
        self.event_manager.send_logout_event.connect(self.client.send_logout_request)
        
    async def asyncTearDown(self):
        """
        Clean up after each test case.
        """
        await super().asyncTearDown()
        
    def tearDown(self):
        self.app.quit()
        
    @patch("app.network.Session_client.ssl.SSLContext")
    def test_configure_ssl_context(self, mock_ssl_context):
        """
        Test if the SSL context is configured properly.
        """
        logger.info("Started: test_configure_ssl_context")
        
        mock_ssl_instance = mock_ssl_context.return_value
        context = self.client._configure_ssl_context()

        self.assertEqual(context, mock_ssl_instance)
        mock_ssl_context.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        mock_ssl_instance.load_cert_chain.assert_called_once_with(
            certfile=Config.CERT_PATH, keyfile=Config.KEY_PATH
        )
        mock_ssl_instance.load_verify_locations.assert_called_once_with(cafile=Config.CA_PATH)
        
        logger.info("Test passed: test_configure_ssl_context")
        
    @patch("app.network.Session_client.aiohttp.ClientSession")
    async def test_create_session(self, mock_client_session):
        """
        Test session creation with correct configurations.
        """
        logger.info("Started: test_create_session")
        await self.client.create_session()

        mock_client_session.assert_called_once_with(
            connector=mock_client_session.call_args[1]['connector'],
            timeout=mock_client_session.call_args[1]['timeout']
        )
        self.assertIsInstance(self.client.session_timeout, ClientTimeout)
        self.assertEqual(self.client.session_timeout.total, int(Config.REQUEST_TIMEOUT))
        logger.info("Test passed: test_create_session")
     
    async def test_close_session(self):
        """
        Test session closure behavior.
        """
        logger.info("Started: test_close_session")
        QTimer.singleShot(5, self.app.quit)

        self.app.aboutToQuit.connect(self.client.close_session)

        self.loop.run_forever()

        self.client.session.close.assert_awaited_once()
        
        logger.info("Test passed: test_close_session")
        
    def test_get_header(self):
        """
        Test if headers are correctly merged with additional values.
        """
        logger.info("Started: test_get_header")
        additional_headers = {"X-Test-Header": "TestValue"}
        result = self.client.get_header(additional_headers)

        self.assertIn("X-Test-Header", result)
        self.assertEqual(result["X-Test-Header"], "TestValue")
        self.assertTrue(all(key in result for key in Config.HEADERS.keys()))
        
        logger.info("Test passed: test_get_header")
        
    async def test_send_login_request_success(self):
        """
        Test successful login request and event emission.
        """
        logger.info("Started: test_send_login_request_success")
        async def mock_aenter(_):
            mock_response = AsyncMock()
            mock_response.json.return_value = {"key": "value"} 
            mock_response.status = 200
            return mock_response

        async def mock_aexit(obj, exc_type, exc, tb):
            return None
        
        self.client.session.post.return_value.__aenter__ = mock_aenter
        self.client.session.post.return_value.__aexit__ = mock_aexit
        
        self.event_manager.send_login_event.emit({"username": "test", "password": "pass", "code": "1234"})

        await asyncio.sleep(1)

        self.client.addEvent.emit.assert_called_once_with(
            0, "handle_login", {"key": "value", "status": 200}, self.client.__class__.__name__
        )
        
        logger.info("Test passed: test_send_login_request_success")
        
    async def test_send_login_request_unauthorized(self):
        """
        Test handling of a 401 Unauthorized response during login request.
        """
        logger.info("Started: test_send_login_request_unauthorized")
        async def mock_aenter(*args, **kwargs):
            mock_response = AsyncMock()
            mock_response.json.return_value = {"error": "Unauthorized"}
            mock_response.status = 401 
            return mock_response

        async def mock_aexit(obj, exc_type, exc, tb):
            return None

        self.client.session.post.return_value.__aenter__ = mock_aenter
        self.client.session.post.return_value.__aexit__ = mock_aexit

        self.event_manager.send_login_event.emit({"username": "test", "password": "pass", "code": "1234"})
        
        await asyncio.sleep(1)

        self.client.addEvent.emit.assert_called_once_with(
            0, "handle_login", {"error": "Unauthorized", "status": 401}, self.client.__class__.__name__
        )
        
        logger.info("Test passed: test_send_login_request_unauthorized")
        
    async def test_send_login_request_timeout(self):
        """
        Test handling of a timeout exception during login request.
        """
        logger.info("Started: test_send_login_request_timeout")
        
        self.client.session.post.side_effect = asyncio.TimeoutError("timeout connection")

        self.event_manager.send_login_event.emit({"username": "test", "password": "pass", "code": "1234"})
        
        await asyncio.sleep(1)
            
        self.client.addEvent.emit.assert_called_once_with(
            0, "handle_login", {'exception': 'timeout connection'}, self.client.__class__.__name__
        )
        
        logger.info("Test passed: test_send_login_request_timeout")
      
    async def test_send_login_request_ssl_error(self):
        """
        Test handling of an SSL exception during login request.
        """
        logger.info("Started: test_send_login_request_ssl_error")
        
        connection_key = ConnectionKey(
                        host="example.com", port=443, is_ssl=True, ssl=None, proxy=None, proxy_auth=None,
                        proxy_headers_hash=None
        )

        error = ClientSSLError(
            connection_key=connection_key,
            os_error=OSError("SSL certificate verification failed")
        )
        self.client.session.post.side_effect = error

        self.event_manager.send_login_event.emit({"username": "test", "password": "pass", "code": "1234"})
        
        await asyncio.sleep(1)

        self.client.addEvent.emit.assert_called_once_with(
            0, "handle_login", {'exception': 'Cannot connect to host example.com:443 ssl:None [None]'}, self.client.__class__.__name__
        )
        
        logger.info("Test passed: test_send_login_request_ssl_error")
        
    async def test_send_refresh_request_success(self):
        """
        Test successful refresh request and event emission.
        """
        logger.info("Started: test_send_refresh_request_success")
        async def mock_aenter(_):
            mock_response = AsyncMock()
            mock_response.json.return_value = {"key": "value"} 
            mock_response.status = 200
            return mock_response

        async def mock_aexit(obj, exc_type, exc, tb):
            return None
        
        self.client.session.post.return_value.__aenter__ = mock_aenter
        self.client.session.post.return_value.__aexit__ = mock_aexit
        
        token_data = {'access_token':"test_token",'expires_in':500,'refresh_token':"test_refresh_token"}
        access_token, refresh_token = create_tokens(token_data)
        
        data = {"access_tokens":[{"token":access_token.token}],"refresh_tokens":[{"token":refresh_token.token}]}
        
        self.event_manager.send_refresh_token_event.emit(data)

        await asyncio.sleep(1)

        self.client.addEvent.emit.assert_called_once_with(
            0, "handle_refresh_token", {"key": "value", "status": 200}, self.client.__class__.__name__
        )
        
        logger.info("Test passed: test_send_refresh_request_success")
        
    async def test_send_logout_request_success(self):
        """
        Test successful logout request and event emission.
        """
        logger.info("Started: test_send_logout_request_success")
        async def mock_aenter(_):
            mock_response = AsyncMock()
            mock_response.json.return_value = {"key": "value"} 
            mock_response.status = 200
            return mock_response

        async def mock_aexit(obj, exc_type, exc, tb):
            return None
        
        self.client.session.post.return_value.__aenter__ = mock_aenter
        self.client.session.post.return_value.__aexit__ = mock_aexit
        
        self.event_manager.send_logout_event.emit("test_token")

        await asyncio.sleep(1)

        self.client.addEvent.emit.assert_called_once_with(
            0, "handle_logout", {"key": "value", "status": 200}, self.client.__class__.__name__
        )
        
        logger.info("Test passed: test_send_logout_request_success")
        
