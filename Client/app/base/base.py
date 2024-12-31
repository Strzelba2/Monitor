from PyQt6.QtCore import QObject,pyqtSlot,pyqtSignal
from app.exceptions.error_manager import ErrorManager

import logging

logger = logging.getLogger(__name__)

class ExceptionHandlerMixin(QObject):
    """
    A mixin for handling exceptions in a PyQt-based application.

    Attributes:
        addEvent (pyqtSignal): A signal emitted to add events to a central manager.
    """
    addEvent = pyqtSignal(int,str,dict,str)
    
    def __init__(self, parent: QObject = None) -> None:
        """
        Initialize the ExceptionHandlerMixin.

        Args:
            parent (QObject, optional): The parent object for this mixin. Defaults to None.
        """
        super().__init__(parent)
        self._error_manager = ErrorManager()
        logger.debug("ExceptionHandlerMixin initialized.")

    @pyqtSlot(Exception, str, dict, str)
    def cqm_process_exception(self, exception: Exception, event_type: str, payload: dict, module: str) -> None:
        """
        Handle exceptions and determine the action based on occurrence count.

        Args:
            exception (Exception): The exception that was raised.
            event_type (str): The type of the event that caused the exception.
            payload (dict): The payload associated with the event.
            module (str): The module where the exception occurred.
        """
        logger.debug(
            f"Processing exception in module '{module}' for event type '{event_type}' with payload: {payload}"
        )
        
        if module == str(type(self).__name__):
            logger.error(f"{type(self).__name__} caught its own exception: {exception}")

            occurrence = self._error_manager.track_exception(module, event_type)
            logger.info(f"Exception occurrence count: {occurrence}")

            if occurrence == 1:
                logger.warning(f"First exception in {module} for '{event_type}'. Retrying...")
                self.addEvent.emit(0, event_type, payload, module)
                logger.debug(f"Emitted addEvent with event_type='{event_type}', payload={payload}, module='{module}'.")
            elif occurrence == 2:
                logger.critical(f"Critical exception in {module} for '{event_type}'.")
                self._error_manager.showCriticalError.emit(f"Critical exception in {module} for '{event_type}'.")
                logger.debug("Critical error signal emitted.")
            else:
                logger.error(f"exceptions for {module}, event '{event_type}'.")
                self._error_manager.showCriticalError.emit(f"exception in {module} for '{event_type}'.")