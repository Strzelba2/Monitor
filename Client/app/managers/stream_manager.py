from PyQt6.QtGui import QImage
from qasync import asyncSlot,asyncClose
from app.signals.signal_menager import SignalManager
from app.network.server_Client import ServerClient
from app.base.base import ExceptionHandlerMixin
from app.exceptions.connection_exc import UnauthorizedConnectionError
from config.config import Config
from datetime import datetime, timezone
from typing import Optional, Dict
import asyncio

import logging

logger = logging.getLogger(__name__)

class StreamManager(ExceptionHandlerMixin, SignalManager):
    """
    Manages streaming functionality, including starting, stopping, and handling video streams.
    """
    
    def __init__(self, parent=None) -> None:
        """
        Initializes the StreamManager instance.
        
        Args:
            parent (Optional[QObject]): The parent object, if any.
        """
        super().__init__(parent)
        self.server_client = ServerClient() 
        self._task: Optional[asyncio.Future] = None
        self.running = False
        self.width = None
        self.height = None
        self.monitor = None
        
    def logout_session(self) ->None:
        """
        Logs out the current session by stopping the video stream and emitting a logout event.
        
        This method stops any ongoing video stream, constructs a logout event payload, 
        and emits an event to notify other components of the session termination.
        """
        logger.info("Logging out session and stopping stream...")
        
        self.stop_stream()
        data = {
            "event":"logout_session",
            "data":{}
        }
        
        logger.debug(f"Emitting logout event with data: {data}")
        self.addEvent.emit(2,"request_with_token",data,type(self).__name__)
        
        logger.info("Logout session event emitted successfully.")
        
    async def _start_stream(self, session_id:str,  hmac:str) -> None:
        """
        Starts a video stream using the provided session credentials.
        
        Args:
            session_id (str): The session identifier.
            hmac (str): The HMAC authorization token.
        """
        logger.info("Starting stream...")
        timestamp = str(int(datetime.now(timezone.utc).timestamp()))
        authorization = f"{session_id}:{hmac}:{timestamp}"
        self.server_client.running = True

        self.monitor = 1  # Default to monitor 1, this could be configurable
        
        url = f"{Config.SERVER_URL}video?width={self.width}&height={self.height}&monitor={self.monitor}"
        
        async for frame in self.server_client.send_stream_request(url, authorization):
            self.process_frame(frame)
            
    async def _close_session(self) -> None:
        """
        Closes the server session and stops the stream if it is running.
        """
        try:
            if self.server_client.running:
                self.stop_stream()
            await self.server_client.close_session()
        except Exception as e:
            logger.error(f"Error while closing a session: {e}")
            
    @asyncSlot(dict)
    async def handle_stream(self, kwargs: Dict) -> None:
        """
        Handles stream initiation based on received session parameters.
        
        Args:
            kwargs (Dict): A dictionary containing session parameters such as 'status', 'token', and 'session_id'.
        """
        logger.debug(f"handle_stream with kwargs: {kwargs}")
        try:
            if("status" in kwargs):
                logger.info("Received a valid response from Session Server")
                if kwargs["status"] == 200:
                    token = kwargs["token"]
                    session_id = kwargs["session_id"]
                    await self._start_stream(session_id,token) 
                    
                else:
                    logger.warning("Authorization header validation failed")
                    self._error_manager.emit_error(f"authorization header failed")
                    self.logout_session()  
            else:
                self._error_manager.emit_critical_error("Applications have faced a critical issue.Please contact the administrator")
                self._error_manager.track_exception(self.__class__.__name__, self.handle_stream.__name__, False)
            
            logger.info("Stream handling completed")
        except UnauthorizedConnectionError as e:
            logger.error("Unauthorized connection error occurred")
            self._error_manager.emit_error(str(e))
            self.logout_session()
        except ValueError as e:
            self._close_session()
            self._error_manager.emit_error(str(e))
        except Exception as e:
            logger.error(f"Unexpected error while handling stream: {e}")
            self._close_session()
            self._error_manager.emit_error(str(e))
        

    def change_image_size (self, width:int, height:int) -> None:
        """
        Updates the image dimensions for the video stream.
        
        Args:
            width (int): The new width of the stream.
            height (int): The new height of the stream.
        """
        logger.info(f"Changing image size to {width}x{height}")
        if width != self.width:
            self.width = width
        if height != self.height:
            self.height = height
      
    @asyncSlot()  
    async def close_server_session(self) -> None:
        """
        Closes the current server session asynchronously.
        """
        await self._close_session()
     
    @asyncClose   
    async def close_server(self) -> None:
        """
        Asynchronously closes the server and terminates any active sessions.
        """
        await self._close_session()
           
    def process_frame(self, frame: bytes) -> None:
        """
        Processes a single video frame.
        
        Args:
            frame (bytes): The raw byte data of the video frame.
        """
        logger.debug("Processing frame data")
        
        start_index = frame.find(b'\xff\xd8')
        if start_index == -1:
            logger.warning("No valid image data found in frame")
            return
        
        image_data = frame[start_index:]
        
        image = QImage()
        if not image.loadFromData(image_data, "JPEG"): 
            logger.error("Failed to load image")
            return

        logger.info("Image successfully loaded and updated")
        self.imageUpdated.emit(image)
 
    def stop_stream(self) -> None:
        """
        Stops the video stream and resets parameters.
        """
        logger.info("Stopping stream...")
        self.server_client.running = False
        self.width = None
        self.height = None