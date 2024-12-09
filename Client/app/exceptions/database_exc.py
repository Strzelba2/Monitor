class BaseManagerError(Exception):
    """
    Base class for all custom exceptions related to manager errors.

    This class is used as the foundation for all custom exceptions in the project. It provides 
    a custom error message that can be passed when the exception is raised.

    Args:
        message (str): The error message describing the exception.
    
    Methods:
        __str__(): Returns the error message for display.
    """
    
    def __init__(self, message: str) -> None:
        """
        Initializes the BaseManagerError exception with a custom error message.

        Args:
            message (str): The error message to describe the exception.
        """
        super().__init__(message)

    def __str__(self) -> str:
        """
        Returns the error message when the exception is converted to a string.

        Returns:
            str: The error message passed during initialization.
        """
        return self.args[0]

class SessionManagerError(BaseManagerError):
    """
    Exception raised for errors occurring in the session manager.

    This class extends BaseManagerError and is specifically used for errors encountered 
    during session management processes.

    Inherits from:
        BaseManagerError: Base class for all custom exceptions.
    """
    pass
    
class TokenManagerError(BaseManagerError):
    """
    Exception raised for errors occurring in the token manager.

    This class extends BaseManagerError and is specifically used for errors encountered 
    during token management operations, such as token creation or validation.

    Inherits from:
        BaseManagerError: Base class for all custom exceptions.
    """
    pass
    
class SettingsManagerError(BaseManagerError):
    """
    Exception raised for errors occurring in the settings manager.

    This class extends BaseManagerError and is specifically used for errors related 
    to loading, saving, or updating user settings.

    Inherits from:
        BaseManagerError: Base class for all custom exceptions.
    """
    pass

class CriticalDatabaseError(BaseManagerError):
    """
    Exception raised for critical database errors.

    This class extends BaseManagerError and is used to indicate a severe database error 
    that may require immediate attention. It is typically used when the database connection 
    fails or when a critical operation cannot be completed.

    Inherits from:
        BaseManagerError: Base class for all custom exceptions.
    """
    pass