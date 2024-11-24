from rest_framework.response import Response

class SecretServerError(Exception):
    """
    Custom exception raised when there is an error with the Secret Server.

    Attributes:
        response (Response): The HTTP response object containing details
                             about the error from the Secret Server.
    """
    def __init__(self, response: Response) -> None:
        """
        Initializes SecretServerError with the response object.

        Args:
            response (Response): The HTTP response object with error details.
        """
        self.response = response
        
    def __str__(self) -> str:
        """
        Returns a string representation of the error.

        Returns:
            str: A string describing the error response.
        """
        return self.response
        
class RedisConnectionError(Exception):
    """
    Custom exception raised when there is an issue connecting to Redis.

    Attributes:
        message (str): Description of the connection error.
    """
    
    def __init__(self, message: str) -> None:
        """
        Initializes RedisConnectionError with a specific error message.

        Args:
            message (str): The message detailing the connection issue.
        """
        super().__init__(message)

    def __str__(self) -> str:
        """
        Returns the error message when the exception is converted to a string.

        Returns:
            str: The error message.
        """
        return self.args[0]