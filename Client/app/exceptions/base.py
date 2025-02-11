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