from PyQt6.QtCore import QObject
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class SessionState(Enum):
    """
    Enumeration representing the different states of a user session.
    """
    SESSION_EXPIRED = "session_expired"
    SESSION_AVAILABLE = "session_available"
    RENEWING_SESSION = "renewing_session"
    SESSION_UNAVAIABLE = "session_unavailable"
    
class LoginState(Enum):
    """
    Enumeration representing the different states of user login.
    """
    LOGGED_OUT = "logged_out"
    IN_REQUEST = "in_request"
    LOGGED_IN = "logged_in"
    

class AppState(QObject):
    """
    Class to manage the application's state, including login and session states.
    """
    def __init__(self, parent: QObject = None):
        """
        Initializes the AppState object.

        Args:
            parent (QObject): The parent QObject, if any. Typically used for signal management.
        """
        super().__init__(parent)
        self.signal_manager = parent 
        self._state = LoginState.LOGGED_OUT
        self._session_state = SessionState.SESSION_UNAVAIABLE
        
        logger.info("AppState initialized with default states: "
                    f"LoginState={self._state}, SessionState={self._session_state}")
                