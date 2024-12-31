from PyQt6.QtCore import QObject, pyqtSignal

from config.config import Config

import logging
import os
import json

logger = logging.getLogger(__name__)

class SingletonMeta(type(QObject), type):
    """
    Metaclass for creating singleton QObject-based classes.

    Ensures that only one instance of a class is created.
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

class ErrorManager(QObject, metaclass=SingletonMeta):
    """
    Manages errors and exception tracking within the application.

    Attributes:
        showError (pyqtSignal): Signal to emit non-critical error messages.
        showCriticalError (pyqtSignal): Signal to emit critical error messages.
        json_file_path (str): Path to the JSON file storing the exception registry.
        registry (dict): Dictionary to track exception occurrences.
    """
    
    showError = pyqtSignal(str)
    showCriticalError = pyqtSignal(str)

    def __init__(self, parent: QObject = None) -> None:
        """
        Initialize the ErrorManager.

        Args:
            parent (QObject, optional): The parent QObject. Defaults to None.
        """
        super().__init__(parent)
        self.json_file_path = Config.EXCEPTION_EVENT_FILE
        self.registry = self._load_registry()
        logger.info("ErrorManager initialized")
        
    def _load_registry(self) -> dict:
        """
        Load the exception registry from a JSON file.

        Returns:
            dict: The loaded registry, or an empty dictionary if the file doesn't exist 
                  or fails to load.
        """
        if not os.path.exists(self.json_file_path):
            logger.info(f"Registry file '{self.json_file_path}' does not exist. Initializing empty registry.")
            try:
                with open(self.json_file_path, "w") as file:
                    json.dump({}, file, indent=4)  
            except IOError as e:
                logger.critical(f"Failed to create registry file '{self.json_file_path}': {e}")
                return {}
        try:
            if os.path.getsize(self.json_file_path) == 0:
                logger.warning(f"Registry file '{self.json_file_path}' is empty. Initializing with an empty dictionary.")
                return {}
            
            with open(self.json_file_path, "r") as file:
                return json.load(file)
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load registry from '{self.json_file_path}': {e}")
            return {}
        
    def _save_registry(self) -> None:
        """Save the current registry to the JSON file."""
        logger.info("Saving registry to file.")
        try:
            with open(self.json_file_path, "w") as file:
                json.dump(self.registry, file, indent=4)
            logger.info("Registry successfully saved.")
        except IOError as e:
            logger.critical(f"Failed to save registry to '{self.json_file_path}': {e}")
            raise e
            
    def track_exception(self, module: str, event_type: str, return_count: bool = True) -> int | None:
        """
        Track an exception occurrence and optionally return the updated count.

        Args:
            module (str): The module name where the exception occurred.
            event_type (str): The type of the event related to the exception.
            return_count (bool): Whether to return the updated count.

        Returns:
            int | None: The updated count of exceptions for the given module and event type,
                        or None if return_count is False.
        """
        logger.info(f"Tracking exception for module '{module}' and event type '{event_type}'.")
        key = f"{module}-{event_type}"
        registry = self.registry.copy()
        
        if key not in self.registry:
            self.registry[key] = 1
            logger.debug(f"New exception tracked for key: {key}. Count set to 1.")
        else:
            self.registry[key] += 1
            logger.debug(f"Incremented exception count for key: {key}. New count: {self.registry[key]}.")

        try:
            self._save_registry()
        except IOError as e:
            logger.error(f"Failed to save updated registry after tracking exception: {e}")
            self.registry = registry
            return None
        
        if return_count:
            logger.info(f"Returning updated count for key '{key}': {self.registry[key]}.")
            return self.registry[key]
            
    def reset_exception(self):
        """
        Clears all events for specified modules from the registry.

        Removes exception events associated with specific modules and updates the registry.
        """
        modules = ["SessionClient","UserManager","SessionViewModel"]
        logger.info(f"Resetting exceptions for modules: {modules}.")
        keys_to_remove = [key for key in self.registry if key.split("-")[0] in modules]
        
        if keys_to_remove:
            for key in keys_to_remove:
                del self.registry[key]
            logger.info(f"Cleared all events for modules '{modules}' from the registry.")
            try:
                self._save_registry()
            except IOError as e:
                logger.error(f"Failed to save updated registry after tracking exception: {e}")
        else:
            logger.warning(f"No events found for modules '{modules}' to clear.")
    
    def emit_error(self, error_message: str) -> None:
        """
        Emit a non-critical error signal.

        Args:
            error_message (str): The error message to emit.
        """
        logger.info(f"Emitting non-critical error: {error_message}")
        self.showError.emit(error_message)
        
    def emit_critical_error(self, error_message: str) -> None:
        """
        Emit a critical error signal.

        Args:
            error_message (str): The critical error message to emit.
        """
        logger.info(f"Emitting critical error: {error_message}")
        self.showCriticalError.emit(error_message)