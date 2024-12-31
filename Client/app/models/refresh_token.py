import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class RefreshTokenManager:
    """
    Manages periodic refresh of tokens using asyncio.

    Attributes:
        refresh_interval (Optional[int]): Time interval in seconds for refreshing the token.
        is_running (bool): Indicates whether the token refresh process is running.
        _task (Optional[asyncio.Future]): The asyncio task running the refresh process.
        event_loop (asyncio.AbstractEventLoop): The asyncio event loop used to schedule tasks.
    """
    def __init__(self):
        """
        Initializes the RefreshTokenManager.

        Sets up default values for attributes and fetches the current running event loop.
        """
        self.refresh_interval: Optional[int] = None
        self.is_running: bool = False
        self._task: Optional[asyncio.Future] = None
        self.event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
        logger.debug("RefreshTokenManager initialized.")
        
    async def _refresh_token(self) -> None:
        """
        Internal coroutine to refresh the token at regular intervals.
        """
        from .user_manager import UserManager
        try:
            while self.is_running:
                logger.debug(f"Sleeping for {self.refresh_interval} seconds before refreshing the token.")
                await asyncio.sleep(self.refresh_interval) 
                logger.debug("Refreshing token...")
                await UserManager.notify_token_refreshed() 
                logger.info("Token refreshed send signal successfully.")
        except asyncio.CancelledError:
            logger.warning("Token refresh task was cancelled.")
        finally:
            logger.debug("Cleaning up after token refresh task.")
            self.is_running = False
            self._task = None
            
    def start(self, refresh_interval: int = 8400) -> None:
        """
        Starts the token refresh process.

        Args:
            refresh_interval (int): Time interval in seconds for refreshing the token. Defaults to 8400 seconds.

        Raises:
            RuntimeError: If no running event loop is found or if a token refresh task is already active.
        """
        logger.debug(f"Attempting to start token refresh with interval {refresh_interval}.")
        logger.debug(f"Current event loop: {self.event_loop}")
        if not self.event_loop:
            raise RuntimeError("No running loop found. Ensure this is called within an event loop context.")
        
        if self._task and not self._task.done():
            logger.info("Token refresh is already running!")
            raise RuntimeError("A token refresh task is already active. Please stop it before starting a new one.")
        
        self.refresh_interval = refresh_interval
        logger.info(f"Starting token refresh with interval {refresh_interval} seconds.")

        logger.info("Token refresh start...")
        try:
            coro = self._refresh_token() 
            self._task = asyncio.create_task(coro)
        except Exception as e:
            if 'coro' in locals() and hasattr(coro, 'close'):
                logger.info("coroutine  is not close")
                coro.close() 
            self.refresh_interval = None
            logger.error(f"Failed to run refresh token timer with : {e}")
            raise e
        
        self.is_running = True  
        
    def stop(self) -> None:
        """
        Stops the token refresh process if it is running.
        """
        if self._task and not self._task.done():
            logger.info("Stopping token refresh process...")
            self.is_running = False
            try:
                self._task.cancel()
                logger.info("Token refresh task cancelled successfully.")
            except asyncio.CancelledError:
                logger.warning(f"Task {self._task} was already cancelled.")
        else:
            logger.info("There is no active task to be stopped.")
        
        
        
        
        
        
        

