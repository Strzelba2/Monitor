from config import Config

import aiohttp
import asyncio
import ssl
import logging

logger = logging.getLogger(__name__)


class SessionClient:
    """
    Handles asynchronous HTTP requests with SSL support, session management, and request locking.
    """
    def __init__(self) -> None:
        """
        Initializes the SessionClient with an SSL context, session timeout, and an async lock.
        """
        self.lock = asyncio.Lock()
        self.ssl_context = self._configure_ssl_context()
        self.session_timeout =   aiohttp.ClientTimeout(
                total=int(Config.REQUEST_TIMEOUT),
                sock_connect=int(Config.REQUEST_TIMEOUT),
                sock_read=int(Config.REQUEST_TIMEOUT)
        )
        self.session = None
        
        logger.info("Session Client initiated successfully")
        
        
    @staticmethod
    def _configure_ssl_context() -> ssl.SSLContext:
        """
        Configure the SSL context for secure connections.

        Returns:
            ssl.SSLContext: Configured SSL context.
        """
        logger.debug("Configuring SSL context")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=Config.CERT_PATH, keyfile=Config.KEY_PATH)
        context.load_verify_locations(cafile=Config.CA_PATH)
        logger.debug("SSL context configured successfully")
        return context
    

    async def create_session(self) -> None:
        """
        Create an asynchronous HTTP session with SSL support.
        """
        logger.info("Creating a new HTTP session")
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=self.ssl_context),
            timeout=self.session_timeout
        )
    
    async def close_session(self) -> None:
        """
        Close the HTTP session if it exists.
        """
        logger.info("Closing HTTP session")
        if self.session:
            await self.session.close()
            self.session = None
            logger.debug("HTTP session closed")
            
    def get_header(self, kwargs: dict) -> dict:
        """
        Construct HTTP headers for requests by merging defaults with additional headers.

        Args:
            kwargs (dict): Additional headers to include in the request.

        Returns:
            dict: Complete headers dictionary.
        """
        logger.debug(f"Setting up additional headers: {kwargs}")
        header = Config.HEADERS.copy() 
        for key in list(kwargs.keys()):  
            if key in header:  
                header[key] = kwargs.pop(key)  
        return {**header, **kwargs} 
    
    async def send_request(self, endpoint: str, method: str = "POST", json_data: dict = None, 
                           headers: dict = None) -> dict:
        """
        Sends a universal HTTP request.

        Args:
            endpoint (str): Path of endpoint (np. "/login/").
            method (str): Metoda HTTP (default "POST").
            json_data (dict): JSON data to send (default None).
            headers (dict): Headers HTTP (default None).
            
        Returns:
            dict: JSON response with added HTTP status.

        Raises:
            Exception: If an unexpected error occurs.
        """
        logger.info(f"Sending {method} request to {endpoint}")
        
        try:
            if self.session is None:
                logger.warning("Session not found, creating a new one")
                await self.create_session()
                
            async with self.lock:
                url = f"https://{Config.DOMAIN}{endpoint}"
                async with getattr(self.session, method.lower())(
                    url, json=json_data, headers=headers
                ) as response:
                    logger.info(f"{method} response: {response.status}")
                    
                    data = await response.json()
                    data["status"] = response.status
                    
                    return data
                
        except Exception as e:
            logger.error(f"Unexcepeted error accured : {e} ")
            raise e