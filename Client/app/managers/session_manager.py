from app.database.session_db_manager import SessionDBManager, SessionData
from .refresh_session import RefreshSessionManager
from sqlalchemy.exc import  SQLAlchemyError
from app.exceptions.database_exc import SessionDBManagerError
from datetime import datetime
from typing import Optional

import logging

logger = logging.getLogger(__name__)

class SessionManager():
    def __init__(self):
        """
        Initialize the SessionManager class.

        Attributes:
            _session_db_manager (SessionDBManager): Manager for session database operations.
            _refresh_session (RefreshSessionManager): Manager for session refresh operations.
            _server_name (Optional[str]): The name of the server associated with the session.
        """
        self._session_db_manager = SessionDBManager()
        self._refresh_session = RefreshSessionManager()
        self._server_name: Optional[str] = None
        
    @property
    def server_name(self) -> Optional[str]:
        """
        Gets the server name.
        
        Returns:
            Optional[str]: The name of the server associated with the session.
        """
        return self._server_name
    
    @server_name.setter
    def server_name(self, value:str) -> None:
        """
        Sets the server name.
        
        Args:
            value (str): The server name to set.
        """
        self._server_name = value

    async def save_session(self, session_data:dict) -> None:
        """
        Saves session data to the database.
        
        Args:
            session_data (dict): A dictionary containing session details.
                Required keys:
                - "sessionId" (str): The session identifier.
                - "expires" (str or datetime): Expiration timestamp.
        
        Raises:
            ValueError: If session_data is missing required keys.
            SessionDBManagerError: If database update fails.
            Exception: For unexpected errors.
        """
        logger.info("Starting the session save process.")

        try:
            expires = session_data["expires"]
            if isinstance(expires, str):
                expires = datetime.fromisoformat(expires)
                
            await self._session_db_manager.update_session(session_data["sessionId"],expires)
            logger.info("Session saved successfully.")
            
        except KeyError as e:
            logger.error(f"Token response missing required key: {e}")
            raise ValueError("Invalid token data format.") from e
        except SessionDBManagerError as e:
            logger.error(f"Failed to update tokens in the database: {e}")
            raise  
        except Exception as e:
            logger.error(f"Unexpected error while saving tokens: {e}")
            raise
        
    async def get_session (self) -> Optional[SessionData]:
        """
        Retrieves the most recent session from the database.
        
        Returns:
            Optional[SessionData]: The retrieved session data, or None if no valid session exists.
        
        Raises:
            SQLAlchemyError: If there is a database-related error.
            Exception: For unexpected errors.
        """
        try:
            session = await  self._session_db_manager.get_session()
            return session

        except SQLAlchemyError as e:
            logger.error(f"Database error while retrieving session: {e}")
            raise
        except Exception as e:
            logger.exception(f"Unexpected error while retrieving session: {e}")
            raise

    async def clear_session(self) -> None:
        """
        Clears all stored sessions from the database.
        
        Raises:
            SQLAlchemyError: If there is a database-related error.
            Exception: For unexpected errors.
        """
        try:
            await self._session_db_manager.clear_sessions()
            logger.info("All sessions cleared successfully.")
            
        except SQLAlchemyError as e:
            logger.error(f"Database error while clearing session: {e}")
            raise
        except Exception as e:
            logger.exception(f"Unexpected error while clearing session: {e}")
            raise

    def start_refresh_timer(self,refresh_interval: int = 8400) -> None:
        """
        Starts the session refresh timer with the given interval.
        
        Args:
            refresh_interval (int, optional): Refresh interval in seconds. Defaults to 8400 seconds (2 hours 20 minutes).
        
        Raises:
            RuntimeError: If the refresh timer fails to start.
            Exception: For unexpected errors.
        """
        try:
            self._refresh_session.start(refresh_interval)
            logger.info(f"Session refresh timer started with interval: {refresh_interval} seconds.")
        except RuntimeError as e:
            logger.error(f"Failed to start refresh timer: {e}")
            raise
        except Exception as e:
            logger.exception(f"Unexpected error while starting refresh timer: {e}")
            raise
    
    async def stop_refresh_timer(self) -> None:
        """
        Stops the session refresh timer.
        
        Raises:
            Exception: For unexpected errors.
        """
        try:
            await self._refresh_session.stop()
            logger.info("Session refresh timer stopped successfully.")
        except Exception as e:
            logger.exception(f"Unexpected error while stopping refresh timer: {e}")
            raise