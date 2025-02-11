from PyQt6.QtGui import QImage
from PyQt6.QtQuick import QQuickImageProvider
from PyQt6.QtCore import Qt,pyqtSignal, pyqtSlot, QSize

import logging

logger = logging.getLogger(__name__)

class StreamDisplay(QQuickImageProvider):
    """
    A QQuickImageProvider that manages and provides streaming images to a Qt Quick interface.

    This class updates and emits signals when a new image is available, allowing the UI 
    to respond dynamically to streamed image data.
    """
    imageChanged = pyqtSignal(QImage)
    
    def __init__(self) -> None:
        """
        Initializes the StreamDisplay with an empty image.
        """
        super().__init__(QQuickImageProvider.ImageType.Image)
        self.image = None

    @pyqtSlot(QImage)
    def updateImage(self, image: QImage) -> None:
        """
        Updates the displayed image and emits a signal if the image has changed.

        Args:
            image (QImage): The new image to be displayed.
        """
        logger.info("Processing image update in StreamDisplay.")
        if self.image != image:
            logger.info("New image detected, updating display.")
            self.image = image  
            self.imageChanged.emit(image)
            logger.info("Image updated successfully.")

    def requestImage(self, id: str, size: QSize) -> tuple[QImage, QSize]:
        """
        Provides the requested image to the QML interface.

        If no image is available, a default black placeholder image of size 600x500 is returned.

        Args:
            id (str): The requested image ID (not used in this implementation).
            size (QSize): The requested size (ignored in this implementation).

        Returns:
            tuple[QImage, QSize]: The current image and its size.
        """
        logger.info("requestImage called.")
        if self.image:
            img = self.image
            logger.debug("Returning existing image.")
        else:
            logger.warning("No image available, returning default black image.")
            img = QImage(600, 500, QImage.Format.Format_RGBA8888)
            img.fill(Qt.GlobalColor.black)
            
        return img,img.size()