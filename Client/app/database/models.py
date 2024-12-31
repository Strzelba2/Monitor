from sqlalchemy import Column, Integer, String, Boolean, DateTime,TypeDecorator
from app.database import Base
from datetime import datetime, timezone, timedelta
import logging

logger = logging.getLogger(__name__)


class AwareDateTime(TypeDecorator):
    """
    Custom SQLAlchemy type for handling timezone-aware datetime objects.
    
    Ensures that datetime values bound to the database are timezone-aware
    and are converted to UTC. Retrieves timezone-naive values from the database
    as UTC-aware.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime, dialect) -> datetime:
        """
        Process a datetime value before binding it to the database.

        Args:
            value (datetime): The datetime value to bind.
            dialect: The database dialect in use.

        Returns:
            datetime: The UTC-aware datetime value.

        Raises:
            ValueError: If the provided value is timezone-naive.
        """
        if value is not None:
            logger.debug("Processing bind parameter for datetime: %s", value)
            if value.tzinfo is None:
                logger.error("The datetime value must be timezone-aware.")
                raise ValueError("The datetime value must be timezone-aware.")
            utc_value = value.astimezone(timezone.utc)
            logger.debug("Converted datetime to UTC: %s", utc_value)
            return utc_value
        return value

    def process_result_value(self, value: datetime, dialect) -> datetime:
        """
        Process a datetime value retrieved from the database.

        Args:
            value (datetime): The datetime value from the database.
            dialect: The database dialect in use.

        Returns:
            datetime: The UTC-aware datetime value.
        """
        if value is not None and value.tzinfo is None:
            logger.debug("Converting naive datetime from database to UTC-aware.")
            return value.replace(tzinfo=timezone.utc)
        return value
        

class UserSettings(Base):
    """
    Represents user-specific settings in the database.
    """
    __tablename__ = 'user_settings'

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=True)
    remember_me = Column(Boolean, default=False)
    
    def __repr__(self):
        """
        Return a string representation of the user settings.
        """
        return f"<UserSettings(id={self.id}, username={self.username}, remember_me={self.remember_me})>"

class SessionData(Base):
    """
    Represents a session in the database.
    """
    __tablename__ = 'session'

    id = Column(Integer, primary_key=True)
    session_id = Column(String, unique=True, nullable=False)
    created_at = Column(AwareDateTime, nullable=False)
    expires_at = Column(AwareDateTime, nullable=False)
    
    def __init__(self, session_id: str, created_at: datetime = None, expires_at: datetime = None):
        """
        Initialize a new session.

        Args:
            session_id (str): Unique identifier for the session.
            created_at (datetime, optional): Creation timestamp. Defaults to now in UTC.
            expires_at (datetime, optional): Expiry timestamp. Defaults to 2 hours from now in UTC.
        """
        self.session_id = session_id
        self.created_at = created_at or datetime.now(timezone.utc)
        self.expires_at = expires_at or (datetime.now(timezone.utc) + timedelta(hours=2))
        logger.info("New session created")
    
    def __repr__(self):
        """
        Return a string representation of the session data.
        """
        return (f"<SessionData(id={self.id}, session_id={self.session_id}, created_at={self.created_at}, "
                f"expires_at={self.expires_at})>")
        
        
class TokenBase(Base):
    """
    Abstract base class for token-related models.
    
    Contains common fields and methods for managing tokens.
    """
    __abstract__ = True 
    id = Column(Integer, primary_key=True)
    token = Column(String, unique=True, nullable=False)
    expires_at = Column(AwareDateTime, nullable=False)

    def to_dict(self) -> dict:
        """
        Convert the token data to a dictionary representation.

        Returns:
            dict: Dictionary containing token details.
        """
        return {
            "id": self.id,
            "token": self.token,
            "expires_at": self.expires_at.isoformat(),
        }
        
    def __str__(self) -> str:
        """
        Return the string representation of the token.
        """
        return self.token
    

class TokenData(TokenBase):
    """
    Represents access tokens in the database.
    """
    __tablename__ = 'token'
    
    def __repr__(self):
        """
        Return a string representation of the token data.
        """
        return f"<TokenData(id={self.id}, token={self.token}, expires_at={self.expires_at})>"

class RefreshTokenData(TokenBase):
    """
    Represents refresh tokens in the database.
    """
    __tablename__ = 'refresh_token'
    
    def __repr__(self):
        """
        Return a string representation of the refresh token data.
        """
        return f"<RefreshTokenData(id={self.id}, token={self.token}, expires_at={self.expires_at})>"

