from PyQt6.QtCore import QObject
from app.signals.signal_menager import SignalManager
from app.appStatus.app_state_manager import  SessionState 
from app.exceptions.connection_exc import UnauthorizedConnectionError
from config.config import Config
import aiohttp
import asyncio
from typing import AsyncGenerator
import logging

logger = logging.getLogger(__name__)

class ServerClient(QObject, SignalManager):
    """
    ServerClient handles streaming data from a server using an asynchronous HTTP session.

    It manages session creation, closure, and sending authenticated streaming requests.
    """
    def __init__(self, parent=None) -> None:
        """
        Initialize the ServerClient with necessary configurations.

        Args:
            parent (QObject, optional): Parent QObject for PyQt integration. Defaults to None.
        """
        super().__init__(parent)
        self.session_timeout =   aiohttp.ClientTimeout(
                total=int(Config.STREAM_TIMEOUT),
                sock_connect=int(Config.STREAM_TIMEOUT),
                sock_read=int(Config.STREAM_TIMEOUT)
        )
        self.session = None
        self.running = False
        self.url = Config.SERVER_URL
        
        logger.info("Server Client initiated successfully")
    
    async def create_session(self) -> None:
        """
        Create an asynchronous HTTP session with SSL support.
        """
        if self.session and not self.session.closed:
            logger.debug("Session already exists and is open.")
            return
        
        logger.info("Creating a new HTTP session")
        
        self.session = aiohttp.ClientSession(
            timeout=self.session_timeout,
            read_bufsize=12 * 1024 * 1024
        )
        
        logger.debug("HTTP session created successfully")

    async def close_session(self) -> None:
        """
        Close the HTTP session if it exists.
        """
        logger.info("Closing HTTP session")
        if self.session and not self.session.closed:
            logger.info("Closing HTTP session")
            await self.session.close()
            logger.debug("HTTP session closed successfully")
            self.session = None

    async def send_stream_request(self, url:str, token:str)-> AsyncGenerator[bytes, None]:
        """
        Send a streaming request to the given URL with authentication.

        Args:
            url (str): The endpoint for streaming data.
            token (str): The authentication token.

        Yields:
            bytes: The received image data chunks.

        Raises:
            UnauthorizedConnectionError: If authentication fails (401 response).
            Exception: For unexpected connection errors.
        """
        logger.info(f"Starting stream request to URL: {url}")
        
        if self.session is None or self.session.closed:
            logger.warning("Session not found, creating a new one")
            await self.create_session()
            
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:        
            
            async with self.session.get(url,headers=headers) as response:
                logger.info(f"Received response: {response.status}")
                if response.status == 200:
                    self.appSessionStateChanged.emit(SessionState.CONNECTED)
                elif response.status == 401:
                    logger.error("Unauthorized access - closing session.")
                    await self.close_session()
                    raise UnauthorizedConnectionError("verification connection failed")
                else:
                    logger.error(f"Unexpected response: {response.status}")
                    await self.close_session()
                    raise Exception("unexpected connection error appeared")

                reader = response.content
                boundary = b"--frame"
                
                logger.info(reader)
                
                try:
                    await asyncio.wait_for(reader.readuntil(boundary), timeout=10.0)
                    logger.info("Streaming started.")
                except asyncio.TimeoutError:
                    logger.error("Timed out waiting for the first frame boundary. Closing session.")
                    await self.close_session()
                    raise Exception("No valid frame received within the expected time.")
                
                while self.running:
                    try:
                        while True:
                            line = await reader.readline()
                            if line == b"\r\n":
                                logger.info("End of image captured")
                                break  
                        image_data = await reader.readuntil(boundary)

                        image_data = image_data.rstrip(boundary).rstrip(b"\r\n")
                        logger.info("Image collection successfully completed")
                        
                        yield image_data
                        
                    except asyncio.IncompleteReadError:
                        logger.error("Stream ended unexpectedly")
                        self.running = False
                        break
                
        except aiohttp.ClientError as e:
            logger.exception(f"HTTP request error: {str(e)}")
            await self.close_session()
            raise
        except asyncio.TimeoutError:
            logger.error("Stream request timed out.")
            await self.close_session()
            raise
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Failed to connect to server: {e}")
            await self.close_session()
            raise
        except ValueError as e:
            logger.error("buffer exceeded")
            await self.close_session()
            raise