from .session_client import SessionClient
from config import Config
import mss
import logging

logger = logging.getLogger(__name__)

class SessionService:
    """
    Handles session verification and server availability updates.
    
    This service interacts with an external session server to verify user sessions 
    and update server availability status.
    """
    def __init__(self):
        """
        Initializes the SessionService with a session client.
        """
        logger.info("Initializing SessionService...")
        self.session_client = SessionClient()
        self.server_name = Config.SERVER_NAME

    async def verify_session(self, token: str ,path: str, encode_body:str, method:str, host:str) -> bool:
        """
        Verifies a session token with the session server.
        
        Args:
            token (str): The authorization token to verify.
            path (str): The request path to validate.
            encode_body (str): The encoded request body.
            method (str): The HTTP method (e.g., GET, POST, PATCH).
            host (str): The host making the request.

        Returns:
            bool: True if the session is valid, False otherwise.
        
        Raises:
            RuntimeError: If the session server response is unexpected.
        """
        logger.info(f"Verifying session for host: {host}, path: {path}, method: {method}")
        headers = self.session_client.get_header({"Referer":f"https://sessionid:8080/verifySession/{self.server_name}"})
        verify_data = {
            'authorization': token,
            'path': path,
            'method': method,
            'encode_body': encode_body,
            "host": host,
        }

        logger.debug(f"Sending session verification request: {verify_data}")
        response = await self.session_client.send_request(
            endpoint=f"/verifySession/{self.server_name}/",
            json_data=verify_data,
            headers=headers,
        )
        
        status = response.get("status")
        
        if status == 200:
            logger.info(f"Session verification successful for token: ....")
            return True
        
        logger.warning(f"Session verification failed. Response: {response}")
        return False
 
    async def server_available(self, server_name: str, available:bool = True) -> None:
        """
        Updates the server availability status in the session server.
        
        Args:
            server_name (str): The name of the server being updated.
            available (bool, optional): The availability status of the server. Defaults to True.
        
        Raises:
            RuntimeError: If the session server response is not successful.
        """
        logger.info(f"Updating server availability: {server_name} -> {available}")
        headers = self.session_client.get_header({"Referer":f"https://sessionid:8080/updateServer/{server_name}"})
        
        sct = mss.mss()
        monitors = sct.monitors
        screens = len(monitors) -1
        
        data={'available': available,'screens':screens}
        
        logger.debug(f"Sending server availability update: {data}")
        response = await self.session_client.send_request(
            endpoint=f"/updateServer/{server_name}/",
            method="PATCH",
            json_data=data,
            headers=headers,
        )
        
        status = response.get("status")
        
        if status != 200:
            logger.error(f"Failed to update server availability. Response: {response}")
            raise RuntimeError(f"Unexpected status code: {response['status']}")
        