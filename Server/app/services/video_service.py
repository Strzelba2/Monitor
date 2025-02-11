# Video handling logic using OpenCV

import cv2
import mss
import numpy as np
import asyncio
import pyautogui 
from config import Config


from typing import AsyncGenerator
import logging

logger = logging.getLogger(__name__) 

class VideoService:
    """
    A service for capturing and streaming screen frames.

    This class handles taking screenshots from a specified monitor, resizing them,
    and streaming the frames as an MJPEG stream.

    Attributes:
        state: The application state containing shared resources such as Redis.
        sct (mss.mss): The MSS object used for screen capturing.
    """
    def __init__(self,state) -> None:
        """
        Initializes the VideoService with the given application state.

        Args:
            state: The application state containing shared resources.
        """
        logger.info("Initializing VideoService...")
        self.sct = mss.mss()
        self.state = state
        
    @property
    def redis(self):
        """
        Provides access to the Redis instance from the application state.

        Returns:
            Redis instance.

        Raises:
            RuntimeError: If Redis is not initialized in the application state.
        """
        logger.debug("Accessing Redis instance...")
        if not hasattr(self.state, "redis"):
            logger.error("Redis is not initialized. Ensure Redis is properly set up.")
            raise RuntimeError("Redis is not initialized yet.")
        return self.state.redis
        
    def resize_frame(self, frame: np.ndarray, width: int, height: int) -> np.ndarray:
        """
        Resizes an image frame to the specified dimensions.

        Args:
            frame (np.ndarray): The image frame to resize.
            width (int): The target width of the resized frame.
            height (int): The target height of the resized frame.

        Returns:
            np.ndarray: The resized image frame.
        """
        logger.debug(f"Resizing frame to {width}x{height}")
        try:
            return cv2.resize(frame, (width, height))
        except cv2.error as e:
            logger.error(f"Failed to resize frame: {e}")
            raise

    def get_screenshot(self, monitor_index: int , width: int, height:int) -> bytes:
        """
        Captures a screenshot from the specified monitor and resizes it.

        Args:
            monitor_index (int): The index of the monitor to capture.
            width (int): The width of the output image.
            height (int): The height of the output image.

        Returns:
            bytes: The JPEG-encoded screenshot.

        Raises:
            ValueError: If the specified monitor index is out of range.
        """
        logger.info(f"Capturing screenshot from monitor {monitor_index}...")
        monitors = self.sct.monitors
        if monitor_index >= len(monitors):
            logger.error(f"Monitor index {monitor_index} is out of range.")
            raise ValueError(f"Monitor index {monitor_index} not found.")
        
        monitor = monitors[monitor_index]
        screenshot = np.array(self.sct.grab(monitor))
        frame = cv2.cvtColor(screenshot, cv2.COLOR_BGRA2BGR)
        
        try:
            cursor_x, cursor_y = pyautogui.position()
            cursor_x -= monitor["left"]
            cursor_y -= monitor["top"]
        except Exception as e:
            logger.warning(f"Failed to retrieve cursor position: {e}")
            cursor_x, cursor_y = 0, 0
        
        arrow_end_x = cursor_x + 10
        arrow_end_y = cursor_y + 10

        cv2.arrowedLine(frame, (arrow_end_x, arrow_end_y), (cursor_x, cursor_y), (255, 255, 255), 3)
        
        resized_frame = self.resize_frame(frame, width, height)
        _, buffer = cv2.imencode(".jpg", resized_frame,[cv2.IMWRITE_JPEG_QUALITY, 50])
        
        logger.debug(f"Screenshot captured, size: {len(buffer.tobytes())} bytes.")
        return buffer.tobytes()
    
    async def frame_generator(self, monitor_index: int , width: int, height:int) -> AsyncGenerator[bytes, None]:
        """
        Generates a continuous stream of video frames from a given monitor.

        Args:
            monitor_index (int): The index of the monitor to capture.
            width (int): The width of the output frame.
            height (int): The height of the output frame.

        Yields:
            bytes: A JPEG-encoded frame wrapped in MJPEG format.

        Handles:
            - RuntimeError: If an issue occurs during screenshot capture.
            - ConnectionError: If the client disconnects.
            - asyncio.CancelledError: If the stream is canceled.
            - General exceptions for robustness.
        """
        logger.info(f"Starting frame generator for monitor {monitor_index}...")
        try:
            while True:
                try:
                    frame = self.get_screenshot(monitor_index, width, height)
                    logger.debug(f"Generated frame of size: {len(frame)} bytes.")
                    
                    yield (
                        b"--frame\r\n"
                        b"Content-Type: image/jpeg\r\n\r\n" + frame + b"\r\n"
                    )
                    await asyncio.sleep(0.02)

                except RuntimeError as e:
                    logger.error(f"Runtime error during frame generation: {e}")
                    self.release()
                    break
                except ConnectionError:
                    logger.warning("Client connection closed. Stopping frame generation.")
                    self.release()
                    break
                except asyncio.CancelledError:
                    logger.info("Frame stream canceled. Decreasing connection count.")
                    await self.redis.decr(Config.CONNECTION_COUNT_KEY)
                    self.release()
                    break
                except Exception as e:
                    logger.error(f"Unhandled exception in frame_generator: {e}")
                    break
        finally:
            self.release()
            logger.info("Frame generator has been shut down.")

    def release(self) -> None:
        """
        Releases resources associated with the screen capture.

        This method properly closes the MSS screen capture session.
        """
        logger.info("Releasing resources and closing MSS session...")
        self.sct.close()
