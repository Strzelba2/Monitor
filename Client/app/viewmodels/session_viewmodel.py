from app.signals.signal_menager import SignalManager
from app.exceptions.database_exc import SettingsDBManagerError,CriticalDatabaseError
from app.appStatus.app_state import LoginState
from app.validators.validators import LoginValidator
from app.base.base import ExceptionHandlerMixin
from PyQt6.QtCore import QObject, pyqtSlot, pyqtProperty
from qasync import asyncSlot
import logging

logger = logging.getLogger(__name__)


class SessionViewModel(ExceptionHandlerMixin , SignalManager):
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
        self.settings = None
        self.__username = None
        self.__password = None
        
        logger.info("SessionViewModel initialized successfully.")
        
    async def initialize_managers(self, manager_class: type) -> None:
        """
        Dynamically initialize a manager and handle initialization errors.
        
        Args:
             manager_class(type): The class of the manager to initialize.
        """
        try:
            logger.info(f"{manager_class.__name__} initialize started .")
            self.settings = await manager_class()
            logger.info(f"{manager_class.__name__} initialized successfully.")
        except SettingsDBManagerError as e:
            logger.error(
                f"Error initializing {manager_class.__name__}: {str(e)}. "
                "Please do not use the switch."
            )
            self._error_manager.emit_error(
                f"Error initializing {manager_class.__name__}: {str(e)}. "
                "Please do not use the switch."
            )
        except CriticalDatabaseError as e:
            logger.error(
                f"Critical database error while initializing {manager_class.__name__}: {e}. "
                "Ensure the database is available."
            )
            self._error_manager.emit_critical_error(
                "No connection to the database. Pressing 'OK' will exit the application."
            )
        except Exception as e:
            logger.exception(f"Unexpected error in {manager_class.__name__} initialization: {e}")
    
    @pyqtProperty(QObject, constant=True)
    def error_manager(self):
        """
        Expose the error manager as a constant PyQt property.

        This property provides access to the error manager object, 
        which is responsible for handling and emitting error signals 
        throughout the application's lifecycle.

        Returns:
            QObject: The error manager instance.
        """
        logger.debug("Accessing error_manager property.")
        return self._error_manager
        
    @pyqtProperty(bool, notify=SignalManager.switchStateChanged)
    def switch_state(self) -> bool:
        """
        Property representing the current state of the switch.

        Resturns:
            (bool): True if the switch is on, False otherwise.
        """
        if not self.settings:
            logger.warning("Settings are not initialized yet.")
            return False
        logger.debug("Accessing switch_state property.")
        status = self.settings.remember_me
        logger.debug(f"switch_state is {'ON' if status else 'OFF'}.")
        return status
    
    @pyqtProperty(str, notify=SignalManager.textUsernameChanged)
    def textUsername(self) -> str:
        """
        Property representing the current username.

        Returns:
            (str): The username as a string.
        """
        logger.debug("Accessing textUsername property.")
        username = self.settings.username
        logger.debug(f"Retrieved username: {username}")
        return username

    @asyncSlot(bool)
    @asyncSlot(bool, str)
    async def handle_switch_toggled(self, state: bool, username: str = None) -> None:
        """
        Handle the switch toggle event. Updates the settings and emits signals.

        Args:
            state(bool): The new state of the switch.
            username(str): Optional username to update in the settings.
        """
        logger.debug(f"handle_switch_toggled called with state={state}, username={username}.")
        try:
            if state:
                logger.debug("Switch turned ON. Updating settings.")
                await self.settings.set_remember_me(state,username)
                self.switchStateChanged.emit()
            else:
                logger.debug("Switch turned OFF. Resetting settings.")
                await self.settings.reset_remember_me()
                self.textUsernameChanged.emit("Username")
                self.switchStateChanged.emit()
        except ValueError as e:
            logger.error(f"Error while handling switch toggle: {e}")
            self._error_manager.emit_error(str(e))
            
    @pyqtSlot()      
    def refresh_state(self)-> None:
        """
        A PyQt slot that emits a signal to indicate the state of a switch has changed.
        
        This method is typically connected to UI elements or triggered programmatically 
        to notify the application when the state of a switch component needs to be updated.

        Emits:
            switchStateChanged: A custom signal that can be connected to other slots or 
            handlers to respond to the state change event.
        """
        self.switchStateChanged.emit()
        
    @pyqtSlot(str,result=bool)    
    def verify_password (self,password:str) -> bool:
        """
        Validates the given password.

        Args:
            password (str): The password to validate.

        Returns:
            bool: True if the password is valid, False otherwise.
        """
        logger.debug(f"Verifying password: {password}")
        try:
            LoginValidator.password_validate(password)
            logger.info("Password validation successful.")
            return True
        except ValueError as e:
            logger.error(f"Password validation failed: {e}")
            self.error_manager.emit_error(str(e))
            return False
        
    @pyqtSlot(str,result=bool)    
    def verify_username (self,username:str) -> bool:
        """
        Validates the given username.

        Args:
            username (str): The username to validate.

        Returns:
            bool: True if the username is valid, False otherwise.
        """
        logger.debug(f"Verifying username: {username}")
        try:
            LoginValidator.username_validate(username)
            logger.info("Username validation successful.")
            return True
        except ValueError as e:
            logger.error(f"Username validation failed: {e}")
            self.error_manager.emit_error(str(e))
            return False
        
    @pyqtSlot(str, str)
    def login(self, username:str, password:str) -> None:
        """
        Starts the login process by validating the username and password.

        Args:
            username (str): The username provided by the user.
            password (str): The password provided by the user.
        """
        logger.info("Login process started...")
        password_valid = self.verify_password(password)
        username_valid = self.verify_username(username)
        
        if not (password_valid and username_valid):
            logger.warning("Login validation failed.")
            return
            
        logger.info("Validation successfully performed")
        self.appStateChanged.emit(LoginState.TWO_FACTORY)
        
        self.__username = username
        self.__password = password
        
        logger.debug("appStateChanged emitted for TWO_FACTORY state.")
        
    @pyqtSlot(str)
    def totp_login(self, code:str) -> None:
        """
        Handles two-factor authentication login using a provided code.

        Args:
            code (str): The two-factor authentication code.
        """
        logger.info("Starting two-factor authentication login.")
        try:
            LoginValidator.code_2fa_validate(code)
        except ValueError as e:
            logger.error(f"Two-factor authentication code validation failed: {e}")
            self.appStateChanged.emit(LoginState.LOGGED_OUT)
            self.error_manager.emit_error(str(e))
            return
          
        logger.info("Two-factor authentication code validated successfully.")
        
        if not self.__username or not self.__username:
            self.appStateChanged.emit(LoginState.LOGGED_OUT)
            self.error_manager.emit_error("Not valid login credentials please re-enter Username and password")
            return
            
          
        data = {
            "username":self.__username,
            "password": self.__password,
            "code":code
        }
        
        self.appStateChanged.emit(LoginState.IN_REQUEST)
        self.addEvent.emit(0,"login",data,type(self).__name__)
  
        self.__username = None
        self.__password = None
        
        logger.info("Login request sent.")
        
    @pyqtSlot(str)    
    def login_failed(self, error: str) -> None:
        """
        Handles login failure and updates the application state.

        Args:
            error (str): The error message to emit.
        """
        logger.error(f"Login failed: {error}")
        self.appStateChanged.emit(LoginState.LOGIN_FAILED)
        self._error_manager.emit_error(error)
        
    @pyqtSlot()    
    def login_success(self) -> None:
        """
        Handles successful login and updates the application state.
        """
        logger.info("Login successful.")
        self._error_manager.reset_exception()
        self.appStateChanged.emit(LoginState.LOGGED_IN)
    
    @pyqtSlot()
    def logout(self) -> None:
        """
        Logs out the current user and emits a logout event.
        """
        logger.debug("Logging out.")
        self.addEvent.emit(0,"logout",{},type(self).__name__)
    
    @pyqtSlot()    
    def logout_success(self) -> None:
        """
        Handles successful logout.
        """
        logger.info("Logout successful.")
        self._error_manager.reset_exception()
        self.logoutSuccess.emit()


        
            
