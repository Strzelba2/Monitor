from app.exceptions.base import BaseManagerError

class UnauthorizedConnectionError(BaseManagerError):
    """
    Exception raised for errors occurring in connection by session or server Client.

    This class extends BaseManagerError and is specifically used for errors encountered 
    during http connection  processes.

    Inherits from:
        BaseManagerError: Base class for all custom exceptions.
    """
    pass