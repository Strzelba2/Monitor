from app.signals.signal_menager import SignalManager
from app.exceptions.database_exc import SettingsDBManagerError,CriticalDatabaseError
from app.appStatus.app_state_manager import LoginState, SessionState , AppState
from app.models.server_model import ServersModel
from app.models.stream_display import StreamDisplay
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
        self._server_model = ServersModel()
        self._stream_display = StreamDisplay()
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
    
    @pyqtProperty(StreamDisplay, constant=True)
    def stream_display(self) -> StreamDisplay:
        """
        Returns the stream display instance.
        """
        return self._stream_display
        
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
    
    @pyqtProperty(ServersModel, constant=True)
    def servers(self) -> ServersModel:
        """
        Returns the servers model instance.
        """
        return self._server_model

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
        data = {
            "event":"logout",
            "data":{}
        }
        self.addEvent.emit(0,"request_with_token",data,type(self).__name__)
    
    @pyqtSlot()    
    def logout_success(self) -> None:
        """
        Handles successful logout.
        """
        logger.info("Logout successful.")
        self.addEvent.emit(0,"close_stream_session",{},type(self).__name__)
        self.appSessionStateChanged.emit(SessionState.SESSION_UNAVAIABLE)
        self._error_manager.reset_exception()
        self.logoutSuccess.emit()
        
    @pyqtSlot(str)
    def get_servers_available(self, search:str= "") -> None:
        """
        Emits an event to request the list of available servers.
        
        Args:
            search (str): The search query for filtering servers.
        """
        logger.debug("Get servers available.")
           
        data = {
            "event":"servers",
            "data":{"search":search}
        }
        self.addEvent.emit(0,"request_with_token",data,type(self).__name__)

        
    @pyqtSlot(str)
    def generate_session(self, server_name:str) -> None:
        """
        Emits an event to generate a session for the given server.
        
        Args:
            server_name (str): The name of the server to create a session for.
        """
        logger.info("Generate session.")
        data = {
            "event":"generate_session",
            "data":{"server_name":server_name}
        }
        
        self.addEvent.emit(0,"request_with_token",data,type(self).__name__)
        
    @pyqtSlot(dict) 
    def servers_available(self, kwargs: dict) -> None:
        """
        Handles the response of available servers.
        
        Args:
            kwargs (dict): The response data containing server availability status and list.
        """
        logger.error(f"Servers available response: {kwargs}")
        if kwargs["status"] == 200:
            self._server_model.load_servers(kwargs["data"])
            self.appSessionStateChanged.emit(SessionState.SESSION_SHOW_SERVERS)
            
    @pyqtSlot(bool)   
    def session_update(self, session_available: bool) -> None:
        """
        Updates the application session state based on availability.
        
        Args:
            session_available (bool): True if the session is available, False otherwise.
        """
        logger.info("Update session")
        if session_available:
            logger.info("Session available.")
            self.appSessionStateChanged.emit(SessionState.SESSION_AVAILABLE)
        else:
            logger.info("Session unavailable.")
            self.appSessionStateChanged.emit(SessionState.SESSION_UNAVAIABLE)
            self._error_manager.emit_error("The session is not available please press Servers to subcribe new one")
            
    @pyqtSlot(int, int)       
    def connect_with_server(self, width: int, height: int) -> None:
        """
        Connects to the server with the given video stream dimensions.
        
        Args:
            width (int): The width of the video stream.
            height (int): The height of the video stream.
        """
        logger.info(f"connect_with_server. with width: {width} and height:{height}")
        data = {
            "event":"stream_view",
            "data":{"method":"GET",
                    "path":"/video" }
        }
        self.updateImageSize.emit(width,height)
        self.addEvent.emit(0,"request_with_token",data,type(self).__name__)
     
    @pyqtSlot()    
    def server_logout(self) -> None:
        """
        Logs out from the server and emits the appropriate event.
        """
        logger.info("Logging out from server.")
        
        data = {
            "event":"logout_session",
            "data":{}
        }
        self.addEvent.emit(2,"request_with_token",data,type(self).__name__) 


        
            
