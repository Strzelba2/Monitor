from app.exceptions.base import BaseManagerError

class SessionDBManagerError(BaseManagerError):
    """
    Exception raised for errors occurring in the session manager.

    This class extends BaseManagerError and is specifically used for errors encountered 
    during session management processes.

    Inherits from:
        BaseManagerError: Base class for all custom exceptions.
    """
    pass
    
class TokenDBManagerError(BaseManagerError):
    """
    Exception raised for errors occurring in the token manager.

    This class extends BaseManagerError and is specifically used for errors encountered 
    during token management operations, such as token creation or validation.

    Inherits from:
        BaseManagerError: Base class for all custom exceptions.
    """
    pass
    
class SettingsDBManagerError(BaseManagerError):
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