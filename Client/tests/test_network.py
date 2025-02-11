import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import ClientSession, ClientTimeout,ClientSSLError
from aiohttp.client_reqrep import ConnectionKey
from aiohttp import web
import aiohttp
from app.network.session_client import SessionClient
from app.network.server_Client import ServerClient
from app.database.data_factory import create_tokens
from app.exceptions.connection_exc import UnauthorizedConnectionError
from config.config import Config
from qasync import QEventLoop
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtCore import QTimer
from PyQt6.QtCore import QObject, pyqtSignal
import asyncio
import time
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
        
    @patch("app.network.session_client.ssl.SSLContext")
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
        
    @patch("app.network.session_client.aiohttp.ClientSession")
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
        
        
class TestServerClient(unittest.IsolatedAsyncioTestCase):
    """
    Test case for the ServerClient class, covering session creation, 
    stream requests, and error handling.
    """
    async def asyncSetUp(self):
        """
        Set up the test case by initializing the ServerClient instance 
        and creating a session.
        """
        self.client = ServerClient()
        self.runner = None
        await self.client.create_session()

    async def asyncTearDown(self):
        """
        Clean up resources after each test by closing the session 
        and stopping the server if it was started.
        """
        if self.runner:
            await self.runner.cleanup()
        await self.client.close_session()
        
    async def set_fake_handler(self, handler):
        """
        Dynamically replace the request handler in the aiohttp server's router.
        
        Args:
            handler (Callable): The request handler function to be added.
        """
        self.app = web.Application()
        self.app.router.add_get("/stream", handler)
        await self.start_server() 
        
    async def start_server(self):
        """
        Start the aiohttp server to apply new routes.
        """
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "localhost", 8081)
        await self.site.start()
        
    async def test_create_session(self):
        """
        Test that a session is successfully created.
        """
        logger.info("Started: test_create_session")
        self.client.session = None
        await self.client.create_session()
        self.assertIsNotNone(self.client.session)
        logger.info("Test Passed: test_create_session")
        
    @patch("aiohttp.ClientSession.get")
    async def test_send_stream_request_success(self, mock_get):
        """
        Test that a successful stream request retrieves the expected frame.
        """
        logger.info("Started: test_send_stream_request_success")
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.content.readuntil = AsyncMock(side_effect=[b"--frame\r\n", b"image_data\r\n--frame"])
        mock_response.content.readline = AsyncMock(return_value=b"\r\n")
        
        mock_get.return_value.__aenter__.return_value = mock_response
        self.client.running = True
        
        url = "http://test.com"
        token = "test_token"
        
        gen = self.client.send_stream_request(url, token)
        
        first_frame = await anext(gen)
        self.assertEqual(first_frame, b"image_data")
        
        logger.info("Test Passes: test_send_stream_request_success")
        
    @patch("aiohttp.ClientSession.get")
    async def test_send_stream_request_unauthorized(self, mock_get):
        """
        Test that an unauthorized stream request raises an exception.
        """
        logger.info("Started: test_send_stream_request_unauthorized")
        mock_response = MagicMock()
        mock_response.status = 401
        mock_get.return_value.__aenter__.return_value = mock_response
        
        url = "http://test.com"
        token = "test_token"
        
        with self.assertRaises(UnauthorizedConnectionError):
            gen = self.client.send_stream_request(url, token)
            await anext(gen)
            
        logger.info("Test Passed: test_send_stream_request_unauthorized")
            
    async def test_send_stream_request_timeout(self):
        """
        Test that a timeout occurs when no valid frame is received from the stream.
        """
        logger.info("Started: test_send_stream_request_timeout")
        self.client.running = True

        url = "http://localhost:8081/stream"
        token = "test_token"
        
        async def fake_stream(request):
            async def stream_response(writer):
                try:
                    for _ in range(100): 
                        await asyncio.sleep(0.1) 
                        await writer.write(b"random_data_without_boundary")
                except (aiohttp.ClientConnectionError, asyncio.CancelledError):
                    print("Client disconnected")
                except Exception as e:
                    print(f"Unexpected error: {e}")

            response = web.StreamResponse(status=200)
            response.content_type = "application/octet-stream"
            await response.prepare(request)
            await stream_response(response)
            return response
        
        await self.set_fake_handler(fake_stream)
        
        with self.assertRaises(Exception) as context:
            gen = self.client.send_stream_request(url, token)
            await anext(gen)
        
        logger.info(f"exception: {context.exception}")
        self.assertIn("No valid frame received", str(context.exception))
        
        logger.info("Test Passed: test_send_stream_request_timeout")
        
    async def test_large_response(self):
        """
        Test that an excessively large response raises an error.
        """
        logger.info("Started: test_large_response")
        self.client.running = True

        url = "http://localhost:8081/stream"
        token = "test_token"
        
        async def fake_stream(request):
            response = web.StreamResponse(status=200)
            response.content_type = "application/octet-stream"
            await response.prepare(request)

            try:
                for _ in range(10**6): 
                    await response.write(b"A" * 1024*1024)  
                    await asyncio.sleep(0.001) 
            except asyncio.CancelledError:
                print("Client disconnected")
            except Exception as e:
                print(f"Error: {e}")

            return response
        
        await self.set_fake_handler(fake_stream)
        
        with self.assertRaises(Exception) as context:
            gen = self.client.send_stream_request(url, token)
            await anext(gen)
        
        logger.info(f"exception: {context.exception}")
        self.assertIn("Chunk too big", str(context.exception))
        
        logger.info("Test Passed: test_large_response")
        
