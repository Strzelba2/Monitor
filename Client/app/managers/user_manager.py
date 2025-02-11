from PyQt6.QtCore import QObject,pyqtSlot
from qasync import asyncSlot,asyncClose 
from typing import Dict

from app.managers.session_manager import SessionManager
from app.managers.token_manager import TokenManager
from app.signals.signal_menager import SignalManager
from app.validators.validators import LoginValidator

from app.base.base import ExceptionHandlerMixin
from config.config import Config

import logging
from datetime import datetime, timezone
import asyncio

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
        self._sesion_manager = SessionManager()
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
                await instance._token_manager.stop_refresh_timer()
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
            
    @classmethod
    async def notify_session_refreshed(cls):
        """
        Notifies that the session has been refreshed and emits an event.
        """
        logger.info("Session refreshed notification initiated.")

        instance = cls._instance
        if cls._instance:
            logger.info(f"UserManage instance exist:  {instance}")
            try:
                await instance._sesion_manager.stop_refresh_timer()
                logger.info("refresh session has been stopped")
                instance.get_token("update_session", {})

            except Exception as e:
                logger.error(f"Exception during session refresh notification: {str(e)}")   
        else:
            logger.error("UserManager instance not initialized.")
            
    async def clear_close_session_server(self) -> None:
        """
        Clears the session and updates the session state..
        """
        logger.info(f"clear_close_session_server")
        await self._sesion_manager.clear_session()
        self._sesion_manager.server_name = None
        self.addEvent.emit(3,"close_stream_session",{},type(self).__name__)
        await asyncio.sleep(0.1)
        self.addEvent.emit(2,"session_update",{"available": False},type(self).__name__)
        
     
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
                    await self._token_manager.start_refresh_timer(refresh_interval)
                    logger.info("Refresh Token timer was started")
                    
                    self.addEvent.emit(0,"login_success",{},type(self).__name__)
                except Exception as e:
                    logger.error(f"Exception during login: {str(e)}")
                    self._token_manager.clear_secret_key()
                    await self._token_manager.clear_tokens()
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
                logger.info(f"refresh_token got response status: {kwargs["status"]} and expires_in:{kwargs['expires_in']}")
                try:
                    await self._token_manager.save_token(kwargs)
                    logger.info("Tokens were written successfully")
                    
                    refresh_interval = int(kwargs['expires_in']) - int(Config.REFRESH_TOKEN_TIME_DELTA)   
                    await self._token_manager.start_refresh_timer(refresh_interval)
                    logger.info("Refresh Token timer was started")
                    
                    self._error_manager.reset_exception()
                except Exception as e:
                    logger.error(f"Exception during token refresh: {str(e)}")
                    self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{str(e)},Please contact the administrator")
                    self._error_manager.track_exception(self.__class__.__name__, self.refresh_token.__name__, False)
            else:
                try:
                    await self._token_manager.stop_refresh_timer()
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
   
    @asyncSlot(str, dict)          
    async def get_token(self, event:str , data:dict) -> None:
        """
        Retrieves the access token for request purposes.
        """
        logger.info("Retrieving token for event:{event}.")
        try:
            access_token = await self._token_manager.get_token_access_token()
            logger.info(f"access_token: {access_token}")
            if access_token:
                logger.debug("Access token exist")
                if event == "logout":
                    logger.info(f"proccesing event:{event}")
                    self.addEvent.emit(0,"send_logout",{"access_token":access_token.token},type(self).__name__)
                
                elif event == "servers":
                    logger.info(f"proccesing event:{event}")
                    self.addEvent.emit(0,"send_servers",{"access_token":access_token.token,"search":data["search"]},type(self).__name__)
                
                elif event == "generate_session":
                    logger.info(f"proccesing event:{event}")
                    session_server_name = self._sesion_manager.server_name
                    if not session_server_name or session_server_name != data["server_name"]:
                        self._sesion_manager.server_name = data["server_name"]
                        self.addEvent.emit(0,"send_generate_session",{"access_token":access_token.token,"server_name":data["server_name"]},type(self).__name__)
                    else:
                        self._error_manager.emit_error(f"server {session_server_name} already  exists in Session manager")
                        
                elif event == "update_session" or event == "logout_session":
                    logger.info(f"proccesing event:{event}")
                    session_id = await self._sesion_manager.get_session()
                    if session_id:
                        logger.info("session exist in database")
                        data = {
                            "event":event,
                            "access_token":access_token.token,
                            "session_id":session_id.session_id
                        }
                        self.addEvent.emit(2,"send_update_session",data,type(self).__name__)
                        
                elif event == "stream_view":
                    logger.info(f"proccesing event:{event}")
                    session_id = await self._sesion_manager.get_session()
                    if session_id:
                        logger.info("session exist")
                        data = {
                            "event":event,
                            "access_token":access_token.token,
                            "server_name":self._sesion_manager.server_name,
                            "session_id":session_id.session_id,
                            "method":data["method"],
                            "path":data["path"]   
                        }
                        self.addEvent.emit(2,"send_get_hmac",data,type(self).__name__)
                else:
                    self._error_manager.emit_critical_error("No valid session the application will be closed")

        except Exception as e:
            logger.error(f"Exception during token retrieval: {str(e)}")
            self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{str(e)},Please contact the administrator")
            self._error_manager.track_exception(self.__class__.__name__, self.get_token.__name__, False)
     
    @asyncSlot(dict)
    async def session(self, kwargs: dict) -> None:
        """
        Handles the session process.

        Args:
            kwargs (dict): Session response data containing status and other parameters.
        """
        if("status" in kwargs):
            if kwargs["status"] == 200:
                logger.info("Generation session was successful...")
                try:
                    if "sessionId" in kwargs:
                        await self._sesion_manager.save_session(kwargs)
                        logger.info("session was written successfully")
                        
                        expires_dt = datetime.fromisoformat(kwargs['expires'])
                        expires_timestamp = int(expires_dt.timestamp())
                        
                        refresh_interval = expires_timestamp - int(Config.REFRESH_TOKEN_TIME_DELTA)   
                        self._sesion_manager.start_refresh_timer(refresh_interval)
                        logger.info("Refresh Token timer was started")
                        
                        self.addEvent.emit(2,"session_update",{"available": True},type(self).__name__)
                    else:
                        await self.clear_close_session_server()

                except Exception as e:
                    logger.error(f"Exception during session refresh: {str(e)}")
                    self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{str(e)},Please contact the administrator")
                    self._error_manager.track_exception(self.__class__.__name__, self.session.__name__, False)
            else:
                try:
                    await self.clear_close_session_server()
                except Exception as e:
                    self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{str(e)},Please contact the administrator")
                    self._error_manager.track_exception(self.__class__.__name__, self.session.__name__, False)
                    return
                self._error_manager.emit_error(f"Session server replied with not correct status:{kwargs["status"]}" )
                
        elif("exception" in kwargs):
            logger.error(f"Session exception: {kwargs['exception']}")
            self._error_manager.emit_critical_error(f"Applications have faced a critical issue:{kwargs["exception"]},Please contact the administrator")
            logger.info("Session Update failed ")

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
                    await self._token_manager.stop_refresh_timer()
                    await self._token_manager.clear_tokens()
                    self._token_manager.clear_secret_key()
                    self._sesion_manager.server_name = None
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
            await self._sesion_manager.clear_session()
            logger.info("Successfully cleared tokens during close operation.")
        except Exception as e:
            logger.error(f"Failed to clear tokens during close operation: {e}")
            raise
        
    async def get_all_tokens(self)-> Dict[str, str]:
        """
        Retrieve all tokens managed by the token manager.

        This asynchronous method interacts with the token manager to fetch all currently available tokens. 
        In case of an error during the retrieval process, an error is logged, and the exception is re-raised.

        Returns:
            dict: A dictionary containing all tokens, where the keys are token identifiers and the values are the tokens themselves.

        Raises:
            Exception: Any exception encountered while attempting to retrieve tokens.
        """
        try:
            tokens = await self._token_manager.get_all_tokens()      
        except Exception as e:
            logger.error(f"Failed to get tokens and session: {e}")
            raise
        return tokens
     
    @asyncClose   
    async def close_clear_tokens_and_session(self) -> None:
        """
        Clears all tokens and session during close operation.
        """
        await self.clear_tokens_and_session()
