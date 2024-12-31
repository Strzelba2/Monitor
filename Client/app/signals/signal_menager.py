from PyQt6.QtCore import QObject, pyqtSignal

from app.appStatus.app_state import LoginState

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
    
    
    #CentralQueueManager
    # addEvent = pyqtSignal(int,str,dict,str)
    send_login_event = pyqtSignal(dict)
    set_secret_key = pyqtSignal(str, str)
    handle_login_event = pyqtSignal(dict)
    login_failed_event = pyqtSignal(str)
    login_success_event = pyqtSignal()
    send_refresh_token_event = pyqtSignal(dict)
    handle_refresh_token_event = pyqtSignal(dict)
    logout_get_token_event = pyqtSignal()
    send_logout_event = pyqtSignal(str)
    handle_logout_event = pyqtSignal(dict)
    logout_success_event = pyqtSignal()
    handle_exception_event = pyqtSignal(Exception,str,dict,str)
    
    #AppState
    appStateChanged = pyqtSignal(LoginState)
    showAppStateChanged = pyqtSignal()
    

    
    
    
    



 