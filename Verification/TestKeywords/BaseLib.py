from PIL import ImageGrab
import base64
import io
import os
from Verification.Config.config import Config

from robot.api import logger

class BaseLib:
    """
    A utility library providing helper methods for capturing screenshots,
    handling file paths, and generating reports with attached screenshots.
    """
    
    def _attach_screenshot_to_report_base64(self) -> None:
        """
        Captures a screenshot, encodes it in Base64 format, and attaches it to an HTML report.
        """
        base64_image = self._capture_screenshot_base64()
        html_image = f'<img src="data:image/jpeg;base64,{base64_image}" width="800px">'
        logger.info(html_image, html=True)
        
    def _capture_screenshot_base64(self) -> str:
        """
        Captures the current screen and encodes the screenshot in Base64 format.

        Returns:
            str: The Base64-encoded screenshot.
        """
        screenshot = ImageGrab.grab()

        buffer = io.BytesIO()
        screenshot.save(buffer, format="JPEG")
        base64_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
        buffer.close()

        return base64_image
    
    def _relative_path(self,relative_path) -> str:
        """
        Converts a relative path into an absolute path based on the application's base directory.

        Args:
            relative_path (str): The relative path to convert.

        Returns:
            str: The absolute path generated from the relative path.

        Raises:
            ValueError: If the `relative_path` argument is not a string.
        """
        if not isinstance(relative_path, str):
            logger.error("Invalid type for relative_path. Expected a string.")
            raise ValueError("All arguments must be strings.")
        
        path = os.path.join(Config.BASE_DIR, *list(relative_path.strip("/").split("/")))
        logger.info(f"Resolved absolute path: {path}")
        
        return path
    
    