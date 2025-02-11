from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QImage

from app.appStatus.app_state import LoginState, SessionState

class SignalManager():
    """
    Manages custom signals for communication between objects in a PyQt application.

    This class defines various signals that can be emitted to notify other parts of the
    application about changes in state, username, or errors. These signals allow objects
    to communicate with each other without direct dependencies, facilitating better 
    decoupling in the application's design.
    """
    #Error manager
    showError = pyqtSignal(str)
    showCriticalError = pyqtSignal(str)
    
    #SessionViewModel
    switchStateChanged = pyqtSignal()
    textUsernameChanged = pyqtSignal(str)
    logoutSuccess = pyqtSignal()
    updateImageSize = pyqtSignal(int,int)
    
    
    
    #CentralQueueManager
    # addEvent = pyqtSignal(int,str,dict,str)
    send_login_event = pyqtSignal(dict)
    set_secret_key = pyqtSignal(str, str)
    handle_login_event = pyqtSignal(dict)
    login_failed_event = pyqtSignal(str)
    login_success_event = pyqtSignal()
    send_refresh_token_event = pyqtSignal(dict)
    handle_refresh_token_event = pyqtSignal(dict)
    get_token_event = pyqtSignal(str, dict)
    send_logout_event = pyqtSignal(str)
    handle_logout_event = pyqtSignal(dict)
    logout_success_event = pyqtSignal()
    send_servers_event = pyqtSignal(str,str)
    send_generate_session_event = pyqtSignal(str,str)
    send_update_session_event = pyqtSignal(dict)
    handle_servers_event = pyqtSignal(dict)
    handle_session_event = pyqtSignal(dict)
    session_update_event = pyqtSignal(bool)
    handle_exception_event = pyqtSignal(Exception,str,dict,str)
    send_get_hmac = pyqtSignal(dict)
    send_request_stream = pyqtSignal(dict)
    close_stream_session = pyqtSignal()
    
    #AppState
    appStateChanged = pyqtSignal(LoginState)
    showAppStateChanged = pyqtSignal()
    appSessionStateChanged = pyqtSignal(SessionState)
    showAppSessionStateChanged = pyqtSignal()
    
    #StreamManager
    imageUpdated = pyqtSignal(QImage)
    

    
    
    
    



 