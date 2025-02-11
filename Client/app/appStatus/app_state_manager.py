from PyQt6.QtCore import QObject, pyqtSlot

from app.signals.signal_menager import SignalManager
from  .app_state import LoginState,SessionState

import logging

logger = logging.getLogger(__name__) 

class AppState(QObject,SignalManager):
    """
    Class to manage the application's state, including login and session states.

    Attributes:
        _state (LoginState): Represents the current login state of the application.
        _session_state (SessionState): Represents the current session state of the application.
    """
    _instance = None

    @staticmethod
    def get_instance():
        """
        Returns the singleton instance of AppState.
        
        If no instance exists, it creates one and returns it.
        
        Returns:
            AppState: The singleton instance of the AppState class.
        """
        if AppState._instance is None:
            logger.info("Creating a new instance of AppState.")
            AppState._instance = AppState()
            
        return AppState._instance
    
    def __init__(self, parent: QObject = None) -> None:
        """
        Initialize the AppState object.

        Args:
            parent (QObject, optional): The parent QObject, if any. Typically used for signal management. Defaults to None.
        """
        if AppState._instance is not None:
            raise Exception("This class is a singleton!")
        
        super().__init__(parent)
        AppState._instance = self
        self._state = LoginState.LOGGED_OUT
        self._session_state = SessionState.SESSION_UNAVAIABLE
      
        logger.info("AppState initialized with default states: "
                    f"LoginState={self._state}, SessionState={self._session_state}")
        
    @pyqtSlot(result=str)
    def get_state(self) -> str:
        """
        Get the current login state of the application.

        Returns:
            str: The string representation of the current login state.
        """
        logger.debug(f"Retrieving current state: {self._state.value}")
        return self._state.value
    
    @pyqtSlot(result=str)
    def get_session_state(self) -> str:
        """
        Get the current Session state of the application.

        Returns:
            str: The string representation of the current Session state.
        """
        logger.info(f"Retrieving current state: {self._session_state.value}")
        return self._session_state.value
    
    @pyqtSlot(LoginState)
    def set_state(self, app_state: LoginState) -> None:
        """
        Set the login state of the application.

        Args:
            app_state (LoginState): The new login state to set.
        """
        logger.info(f"Setting new state: {app_state} (type: {type(app_state)})")
        if self._state == app_state:
            logger.warning(f"App is Already in {app_state} state.")
            return
        self._state = app_state
        self.showAppStateChanged.emit()   
        logger.debug("showAppStateChanged signal emitted.")  
        
    @pyqtSlot(SessionState)
    def set_session_state(self, app_session_state: SessionState) -> None:
        """
        Set the session state of the application.

        Args:
            app_state (SessionState): The new session state to set.
        """
        logger.info(f"Setting new state: {app_session_state} (type: {type(app_session_state)})")
        if self._session_state == app_session_state:
            logger.warning(f"App is Already in {app_session_state} state.")
            return
        
        if app_session_state == SessionState.SESSION_AVAILABLE:
            logger.info(f"App is in {app_session_state} state.")
            if self._session_state == SessionState.CONNECTED:
                logger.warning(f"App is Already connected to  the Server")
                self._session_state = app_session_state
                return
            
        self._session_state = app_session_state
        self.showAppSessionStateChanged.emit()   
        logger.debug("showAppSessionStateChanged signal emitted.") 