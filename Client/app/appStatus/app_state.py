from enum import Enum

class SessionState(Enum):
    """
    Enumeration representing the different states of a user session.
    """
    SESSION_SHOW_SERVERS = "show_servers"
    SESSION_AVAILABLE = "session_available"
    IN_PROGRES = "in_progres"
    CONNECTED = "connected"
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