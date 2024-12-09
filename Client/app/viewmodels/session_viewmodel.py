from app.database.settings_manager import SettingsManager
from app.database.session_manager import SessionManager
from app.database.token_manager import TokenManager
from app.signals.signal_menager import SignalManager
from app.exceptions.database_exc import SettingsManagerError,CriticalDatabaseError
from PyQt6.QtCore import QObject, pyqtSlot, pyqtProperty, pyqtSignal
import logging

logger = logging.getLogger(__name__)


class SessionViewModel(QObject , SignalManager):
    """
    ViewModel for managing the session-related logic and interacting with the Qt framework.
    Handles settings, session, and token management through manager classes.
    """
    
    def __init__(self, parent=None):
        """
        Initialize the SessionViewModel with required managers and connect signals.

        :param parent: Optional parent QObject.
        """
        
        super().__init__(parent)
        self.settings = self.initialize_managers(SettingsManager)
        self.session_manager = self.initialize_managers(SessionManager)
        self.token_manager = self.initialize_managers(TokenManager)
        
        logger.info("SessionViewModel initialized successfully.")
        
    def initialize_managers(self, manager_class: type) -> QObject:
        """
        Dynamically initialize a manager and handle initialization errors.
        
        :param manager_class: The class of the manager to initialize.
        :return: The initialized manager instance or None if initialization fails.
        """
        try:
            manager_instance = manager_class()
            logger.info(f"{manager_class.__name__} initialized successfully.")
            return manager_instance
        except SettingsManagerError as e:
            logger.error(
                f"Error initializing {manager_class.__name__}: {str(e)}. "
                "Please do not use the switch."
            )
            self.showError.emit(
                f"Error initializing {manager_class.__name__}: {str(e)}. "
                "Please do not use the switch."
            )
        except CriticalDatabaseError as e:
            logger.error(
                f"Critical database error while initializing {manager_class.__name__}: {e}. "
                "Ensure the database is available."
            )
            self.showCriticalError.emit(
                "No connection to the database. Pressing 'OK' will exit the application."
            )
        except Exception as e:
            logger.exception(f"Unexpected error in {manager_class.__name__} initialization: {e}")
        return None
        
    @pyqtProperty(bool, notify=SignalManager.switchStateChanged)
    def switch_state(self) -> bool:
        """
        Property representing the current state of the switch.

        :return: True if the switch is on, False otherwise.
        """
        logger.debug("Accessing switch_state property.")
        status = self.settings.remember_me
        logger.debug(f"switch_state is {'ON' if status else 'OFF'}.")
        return status
    
    @pyqtProperty(str, notify=SignalManager.textUsernameChanged)
    def textUsername(self) -> str:
        """
        Property representing the current username.

        :return: The username as a string.
        """
        logger.debug("Accessing textUsername property.")
        username = self.settings.username
        logger.debug(f"Retrieved username: {username}")
        return username

    @pyqtSlot(bool)
    @pyqtSlot(bool, str)
    def handle_switch_toggled(self, state: bool, username: str = None) -> None:
        """
        Handle the switch toggle event. Updates the settings and emits signals.

        :param state: The new state of the switch.
        :param username: Optional username to update in the settings.
        """
        logger.debug(f"handle_switch_toggled called with state={state}, username={username}.")
        try:
            if state:
                logger.debug("Switch turned ON. Updating settings.")
                self.settings.set_remember_me(state,username)
                self.switchStateChanged.emit()
            else:
                logger.debug("Switch turned OFF. Resetting settings.")
                self.settings.reset_remember_me()
                self.textUsernameChanged.emit("Username")
                self.switchStateChanged.emit()
        except ValueError as e:
            logger.error(f"Error while handling switch toggle: {e}")
            self.showError.emit(str(e))
            
    @pyqtSlot()      
    def refresh_state(self,)-> None:
        """
        A PyQt slot that emits a signal to indicate the state of a switch has changed.
        
        This method is typically connected to UI elements or triggered programmatically 
        to notify the application when the state of a switch component needs to be updated.

        Emits:
            switchStateChanged: A custom signal that can be connected to other slots or 
            handlers to respond to the state change event.
        """
        self.switchStateChanged.emit()
        
            
