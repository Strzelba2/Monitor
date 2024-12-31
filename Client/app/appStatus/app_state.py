from enum import Enum

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
    TWO_FACTORY = "two_factory"
    IN_REQUEST = "in_request"
    LOGIN_FAILED = "login_failed"
    LOGGED_IN = "logged_in"