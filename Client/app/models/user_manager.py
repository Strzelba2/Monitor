from PyQt6.QtCore import QObject,pyqtSlot
from qasync import asyncSlot,asyncClose 

# from app.models.session_manager import SessionManager
from app.models.token_manager import TokenManager
from app.signals.signal_menager import SignalManager
from app.validators.validators import LoginValidator

from app.base.base import ExceptionHandlerMixin
from config.config import Config

import logging

logger = logging.getLogger(__name__)

class UserManager(ExceptionHandlerMixin, SignalManager):
    """
    Manages user operations such as login, logout, token refresh, and session clearing.

    Attributes:
        _instance (UserManager): instance of UserManager.
        _token_manager (TokenManager): Manages tokens for user sessions.
        _sesion_manager (SessionManager): Menager session
    """
    
    _instance = None

    def __init__(self, parent=None):
        """
        Initializes the UserManager.

        Args:
            parent: The parent object, if any.
        """
        super().__init__(parent)
        # self._sesion_manager = SessionManager()
        self._token_manager = TokenManager()
        UserManager._instance = self
        logger.info(f"Instance created: {UserManager._instance}")
        
    @classmethod
    async def notify_token_refreshed(cls):
        """
        Notifies that the token has been refreshed and emits an event.
        """
        logger.info("Token refreshed notification initiated.")

        instance = cls._instance
        if cls._instance:
            logger.info(f"UserManage instance exist:  {instance}")
            try:
                instance._token_manager.stop_refresh_timer()
                logger.info("refresh token has been stopped")
                tokens = await instance._token_manager.get_all_tokens()
                if tokens:
                    instance.addEvent.emit(1, "refresh_token", tokens, cls.__name__)
                else:
                    instance._error_manager.emit_critical_error("No valid tokens the application will be closed")
                    
            except Exception as e:
                logger.error(f"Exception during token refresh notification: {str(e)}")
        else:
            logger.error("UserManager instance not initialized.")
     
    @pyqtSlot(str,str)   
    def generate_secret_key(self, code_2fa: str, password: str) -> None:
        """
        Generates a secret key using the provided 2FA code and password.

        Args:
            code_2fa (str): The 2FA code provided by the user.
            password (str): The user's password.
        """
        logger.debug("Generating secret key with 2FA: code_2fa and password.")
        try:
            LoginValidator.code_2fa_validate(code_2fa)
            self._token_manager.generate_secret_key(code_2fa,password)
        except ValueError as e:
            logger.warning(f"Validation failed in UserManager: {str(e)}")
            self._error_manager.emit_error(f"Validation failed in UserManager: {str(e)}")
            self._error_manager.track_exception(self.__class__.__name__, self.generate_secret_key.__name__, False)
        except Exception as e:
            logger.error(f"Secret key generation failed: {str(e)}")
            self._error_manager.emit_critical_error(f"Secret key generation failed: {str(e)}")
            self._error_manager.track_exception(self.__class__.__name__, self.generate_secret_key.__name__, False)

    @asyncSlot(dict)  
    async def login(self,kwargs: dict) -> None:
        """
        Handles user login.

        Args:
            kwargs (dict): Login response data containing status and other parameters.
        """
        logger.info("Handling login process.")
        
        if("status" in kwargs):
            logger.info("User Manager got the correct answer from Session Server")
            if kwargs["status"] == 200:
                logger.info(f"loggin response status : {kwargs["status"]}")
                try:
                    await self._token_manager.save_token(kwargs)
                    logger.info("Tokens were written successfully")
                    
                    refresh_interval = int(kwargs['expires_in']) - int(Config.REFRESH_TOKEN_TIME_DELTA)   
                    self._token_manager.start_refresh_timer(refresh_interval)
                    logger.info("Refresh Token timer was started")
                    
                    self.addEvent.emit(0,"login_success",{},type(self).__name__)
                except Exception as e:
                    logger.error(f"Exception during login: {str(e)}")
                    self._token_manager.clear_secret_key()
                    self._token_manager.clear_tokens()
                    self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{str(e)},Please contact the administrator")
                    self._error_manager.track_exception(self.__class__.__name__, self.login.__name__, False)
            else:
                logger.info(f"loggin failed wit status: {kwargs["status"]}")
                self._token_manager.clear_secret_key()
                self.addEvent.emit(0,"login_failed",{"error":kwargs["error"]},type(self).__name__)    
        elif("exception" in kwargs):
            logger.error(f"Login exception: {kwargs['exception']}")
            self._token_manager.clear_secret_key()
            self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{kwargs["exception"]},Please contact the administrator")
            logger.info("loggin failed ")
        else:
            logger.error(f"Login error with kwargs: {kwargs}")
            self._token_manager.clear_secret_key()
            self.addEvent.emit(0,"login_failed",{"error":f"loggin error with kwargs {kwargs},Please contact the administrator"})

    @asyncSlot(dict) 
    async def refresh_token(self,  kwargs: dict) -> None:
        """
        Refreshes the user token.

        Args:
            kwargs (dict): Response data containing status and other parameters.
        """
        logger.info("Refreshing token.")
        
        if("status" in kwargs):
            logger.info("User Manager got the correct answer from Session Server")
            if kwargs["status"] == 200:
                logger.info(f"refresh_token got response status: {kwargs["status"]}")
                try:
                    await self._token_manager.save_token(kwargs)
                    logger.info("Tokens were written successfully")
                    
                    refresh_interval = int(kwargs['expires_in']) - int(Config.REFRESH_TOKEN_TIME_DELTA)   
                    self._token_manager.start_refresh_timer(refresh_interval)
                    logger.info("Refresh Token timer was started")
                    
                    self._error_manager.reset_exception()
                except Exception as e:
                    logger.error(f"Exception during token refresh: {str(e)}")
                    self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{str(e)},Please contact the administrator")
                    self._error_manager.track_exception(self.__class__.__name__, self.refresh_token.__name__, False)
            else:
                try:
                    self._token_manager.stop_refresh_timer()
                    await self._token_manager.clear_tokens()
                    self._token_manager.clear_secret_key()
                except Exception as e:
                    self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{str(e)},Please contact the administrator")
                    self._error_manager.track_exception(self.__class__.__name__, self.refresh_token.__name__, False)
                    return

                self._error_manager.emit_error(f"Session server replied with not correct status:{kwargs["status"]}" )
                self.addEvent.emit(0,"logout_success",{},type(self).__name__)
                
        elif("exception" in kwargs):
            logger.error(f"Token refresh exception: {kwargs['exception']}")
            self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{kwargs["exception"]},Please contact the administrator")
            logger.info("refresh token failed ")
        else:
            logger.info("Refresh Token error ")
            self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{kwargs["exception"]},Please contact the administrator")
            logger.info("refresh token failed ")
   
    @asyncSlot()          
    async def logout_get_token(self) -> None:
        """
        Retrieves the access token for logout purposes.
        """
        logger.info("Retrieving token for logout.")
        try:
            access_token = await self._token_manager.get_token_access_token()
            if access_token:
                logger.debug("Access token exist")
                self.addEvent.emit(0,"send_logout",{"access_token":access_token.token},type(self).__name__)
        except Exception as e:
            logger.error(f"Exception during token retrieval: {str(e)}")
            self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{str(e)},Please contact the administrator")
            self._error_manager.track_exception(self.__class__.__name__, self.logout_get_token.__name__, False)
            
    @asyncSlot(dict)       
    async def logout(self, kwargs: dict) -> None:
        """
        Handles the logout process.

        Args:
            kwargs (dict): Logout response data containing status and other parameters.
        """
        logger.info("Processing logout.")
        
        if("status" in kwargs):
            if kwargs["status"] == 200:
                logger.info("Logout successful...")
                try:
                    self._token_manager.stop_refresh_timer()
                    await self._token_manager.clear_tokens()
                    self._token_manager.clear_secret_key()
                except Exception as e:
                    logger.error(f"Exception during logout: {str(e)}")
                    self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{str(e)},Please contact the administrator")
                    self._error_manager.track_exception(self.__class__.__name__, self.logout.__name__, False)
                    return
                
                self.addEvent.emit(0,"logout_success",{},type(self).__name__)
            else:
                self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{kwargs["error"]},Please contact the administrator")
        elif("exception" in kwargs):
            logger.warning(f"Logout failed with status: {kwargs['status']}")
            self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{kwargs["exception"]},Please contact the administrator")
            logger.info("loggout failed ")
        else:
            logger.info(f"logout error with kwargs {kwargs}")
            self._error_manager.emit_critical_error(f"Applications have faced a Session Server issue:{kwargs["exception"]},Please contact the administrator")
 
    async def clear_tokens_and_session(self) -> None:
        """
        Clears all tokens and logs the operation result.
        """
        try:
            await self._token_manager.clear_tokens()        
        except Exception as e:
            logger.error(f"Failed to clear tokens and session: {e}")
            raise
     
    @asyncClose   
    async def close_clear_tokens_and_session(self) -> None:
        """
        Clears all tokens and session during close operation.
        """
        try:
            await self._token_manager.clear_tokens()
            logger.info("Successfully cleared tokens during close operation.")
        except Exception as e:
            logger.error(f"Failed to clear tokens during close operation: {e}")
            raise
