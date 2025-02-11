from qasync import asyncSlot,asyncClose

from app.signals.signal_menager import SignalManager
from app.base.base import ExceptionHandlerMixin
from config.config import Config

import aiohttp
import asyncio
import ssl
import logging
import base64

logger = logging.getLogger(__name__)

class SessionClient(ExceptionHandlerMixin, SignalManager):
    """
    Handles session management and API requests with SSL configuration, 
    including login, logout, and token refresh operations.
    """

    def __init__(self, parent=None):
        """
        Initialize the SessionClient with necessary configurations.

        Args:
            parent (QObject, optional): Parent QObject for PyQt integration. Defaults to None.
        """
        super().__init__(parent)
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
   
    @asyncClose   
    async def close_session(self) -> None:
        """
        Close the HTTP session if it exists.
        """
        logger.info("Closing HTTP session")
        if self.session:
            await self.session.close()
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
                           headers: dict = None, event_type: str = None, session_id:str = None):
        """
        Sends a universal HTTP request.

        Args:
            endpoint (str): Path of endpoint (np. "/login/").
            method (str): Metoda HTTP (default "POST").
            json_data (dict): JSON data to send (default None).
            headers (dict): Headers HTTP (default None).
            event_type (str): Name of event to be emitted (default None).
            session_id (str): Session id for generation hmac
        """
        logger.info(f"Sending {method} request to {endpoint}")
        try:
            if self.session is None:
                logger.warning("Session not found, creating a new one")
                await self.create_session()
            
            async with self.lock:
                url = f"https://{Config.DOMAIN}{endpoint}"
                logger.debug(f"request for url: {url}")
                async with getattr(self.session, method.lower())(
                    url, json=json_data, headers=headers
                ) as response:
                    logger.info(f"{method} response: {response.status}")
                    data = await response.json()
                    
                    if isinstance(data, list):
                        data = {
                            "data":data,
                            "status":response.status
                        }
                        
                    elif isinstance(data, dict):
                        data["status"] = response.status
                        
                    if session_id:
                        data["session_id"] = session_id

                    logger.info(f"data: {data}")
                    if event_type:
                        self.addEvent.emit(0, event_type, data, type(self).__name__)
                        
        except Exception as e:
            data = {"exception": str(e)}
            if event_type:
                self.addEvent.emit(0, event_type, data, type(self).__name__)
            logger.error(f"{method} request exception: {str(e)}")
            self._error_manager.track_exception(self.__class__.__name__, self.send_request.__name__, False)

    @asyncSlot(dict) 
    async def send_login_request(self, kwargs: dict) -> None:
        """
        Send an asynchronous login request.

        Args:
            kwargs (dict): Contains login credentials and additional data.
        """
        logger.info("Sending login request")
        headers = self.get_header({
            "X-Verification-Code": kwargs["code"],
            "Referer":"https://sessionid:8080/login/",
            })
        
        await self.send_request(
            endpoint="/login/",
            json_data={"username": kwargs["username"], "password": kwargs["password"]},
            headers=headers,
            event_type="handle_login",
        )

    @asyncSlot(dict)   
    async def send_refresh_token_request(self, kwargs):
        """
        Send a request to refresh an access token.

        Args:
            kwargs (dict): Contains the refresh token and additional data.
        """
        logger.info("Sending refresh token request")
        headers = self.get_header({
                "Authorization": f"Bearer {kwargs["access_tokens"][0]["token"]}"
                })

        await self.send_request(
            endpoint="/refresh/",
            json_data={"refresh_token": kwargs["refresh_tokens"][0]["token"]},
            headers=headers,
            event_type="handle_refresh_token",
        )

    @asyncSlot(str)    
    async def send_logout_request(self, access_token): 
        """
        Send a logout request to invalidate an access token.

        Args:
            access_token (str): The token to be invalidated.
        """
        logger.info("Sending logout request")
        headers = self.get_header({
                "Authorization": f"Bearer {access_token}"
                })
     
        await self.send_request(
            endpoint="/logout/",
            headers=headers,
            event_type="handle_logout",
        )
        
    @asyncSlot(str,str)    
    async def send_servers_request(self, access_token:str, search:str): 
        """
        Send a get servers request to show all available servers.

        Args:
            access_token (str): Request authorization token.
            search (str): filter quary
        """
        logger.info(f"Sending get available servers request with search:{search}")
        headers = self.get_header({
                "Authorization": f"Bearer {access_token}"
                })
     
        await self.send_request(
            endpoint=f"/availableServers/?search={search}" if search else f"/availableServers/?search=''",
            method= "GET",
            headers=headers,
            event_type="handle_servers",
        )
        
    @asyncSlot(str,str)    
    async def send_generate_session_request(self, access_token:str , server_name:str): 
        """
        Send a generate session request .

        Args:
            access_token (str): The token to be invalidated.
            server_name (str):  Name of Server for which the session will be generated
        """
        logger.info("Sending generate session request")
        headers = self.get_header({
                "Authorization": f"Bearer {access_token}"
                })
     
        await self.send_request(
            endpoint="/session/",
            json_data={"server_name": server_name},
            headers=headers,
            event_type="handle_session",
        )
        
        
    @asyncSlot(dict)    
    async def send_update_session_request(self, request_data: dict) -> None: 
        """
        Send a update session request .

        Args:
            request_data (dict): request data 
        """
        logger.info("Sending logout request")
        headers = self.get_header({
                "Authorization": f"Bearer {request_data["access_token"]}"
                })
     
        await self.send_request(
            endpoint="/updateSession/" if request_data["event"] == "update_session" else "/logoutSession/",
            json_data={"session_id": request_data["session_id"]},
            headers=headers,
            event_type="handle_session",
        )
        
    @asyncSlot(dict)    
    async def send_get_hmac_request(self, request_data: dict) -> None:
        """
        Send a get hmac request .

        Args:
            request_data (dict): request data 
        """
        logger.info("send_get_hmac_request")
        headers = self.get_header({
                "Authorization": f"Bearer {request_data["access_token"]}"
                })
        
        encode_body= base64.b64encode(b"").decode()
        
        logger.debug(f"encode_body: {encode_body}")
        
        data = {
            "server_name": request_data["server_name"],
            "method":request_data["method"],
            "encode_body":encode_body,
            "path": request_data["path"]
        }
        
        await self.send_request(
            endpoint="/send/",
            json_data= data,
            headers=headers,
            event_type="handle_stream",
            session_id=request_data["session_id"]
        )


        
        
        
        