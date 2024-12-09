from app.database import SessionLocal
from app.database.models import TokenData, RefreshTokenData
from app.database.base import BaseManager, SingletonMeta
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from datetime import datetime, timezone, timedelta
from config.config import Config
from app.exceptions.database_exc import TokenManagerError
from cryptography.fernet import InvalidToken
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class TokenManager(BaseManager, metaclass=SingletonMeta):
    """
    Manages access and refresh tokens in the database, 
    including creation, validation, updating, and deletion.
    """
    def __init__(self):
        """Initialize the TokenManager with a database session and token mappings."""
        self.db = SessionLocal()
        self.token_classes = {
            "access": TokenData,
            "refresh": RefreshTokenData,
        }
        
        logger.info("TokenManager initialized with a database session.")
        
    def is_timezone_aware(self,dt: datetime) -> bool:
        """
        Check if a datetime object is timezone-aware.
        
        Args:
            dt(datetime): Datetime object to check.
            
        :Return:
            bool:True if timezone-aware, False otherwise.
        """
        return dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None
    
    def is_within_expiry_range(self,expiry: datetime, max_duration: timedelta) -> bool:
        """
        Verify if a datetime is within a specific expiry range.
        
        Args:
            expiry: Expiry datetime to check.
            max_duration: Maximum allowable duration for expiry.
            
        :Return:
            bool: True if within range, False otherwise.
        """
        now = datetime.now(timezone.utc)
        if expiry <= now:
            return False
        return expiry <= now + max_duration
        
    def validate_tokens(self, token: TokenData, refresh_token: RefreshTokenData) -> bool:
        """
        Validate access and refresh tokens for correct expiration and timezone-awareness.
        
        Args:
            token(TokenData): Access token to validate.
            refresh_token(RefreshTokenData): Refresh token to validate.
            
        Return:
            bool: True if both tokens are valid.
           
        Raises: 
            ValueError: If tokens are invalid.
        """
        now = datetime.now(timezone.utc)
        delta = timedelta(minutes=2)
        
        if not self.is_timezone_aware(token.expires_at) or not self.is_timezone_aware(refresh_token.expires_at):
            logger.error("The 'expires_at' timestamp must be timezone-aware.")
            raise ValueError("The 'expires_at' timestamp must be timezone-aware.")
        
        if not self.is_within_expiry_range(token.expires_at, timedelta(minutes=int(Config.TOKEN_EXPIRATION_MINUTES)) + delta):
            logger.error("Access Token expiration timestamp is outside the allowable range.")
            raise ValueError("Access Token expiration timestamp is outside the allowable range.")

        if not self.is_within_expiry_range(refresh_token.expires_at, timedelta(hours=int(Config.REFRESH_EXPIRATION_HOURS)) + delta):
            logger.error("Refresh Token expiration timestamp is outside the allowable range.")
            raise ValueError("Refresh Token expiration timestamp is outside the allowable range.")
        
        logger.info("Tokens validated successfully.")    
        return True
        
    def __create_token(self,token: TokenData, refresh_token: RefreshTokenData) -> None:
        """
        Add access and refresh tokens to the database in a single operation.
        
        Args:
            token(TokenData): Access token to add.
            refresh_token(RefreshTokenDat): Refresh token to add.
        Raises:
            IntegrityError: If a token with the same token already exists.
            SQLAlchemyError: For any database-related issues.
        """
        try:
            token.token = self.encrypt(token.token)
            refresh_token.token = self.encrypt(refresh_token.token)
            self.db.add(token)
            self.db.add(refresh_token)
            self.db.commit()
            logger.info("Tokens created successfully.")
            
        except IntegrityError as e:
            self.db.rollback()
            logger.error(f"IntegrityError while adding tokens: {e}")
            raise  
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.critical(f"Unexpected database error: {e}")
            raise
        except InvalidToken as e:
            logger.error(f"Failed to encrypt token : {e}")
            raise 
        except Exception as e:
            self.db.rollback()
            logger.exception(f"Unknown error while creating tokens: {e}")
            raise

    def update_tokens(self, token: TokenData, refresh_token: RefreshTokenData) -> None:
        """
        Update access and refresh tokens if they already exist; create them otherwise.
        
        Args:
            token(TokenData): New access token data.
            refresh_token(RefreshTokenData): New refresh token data.
        Raises:
            SQLAlchemyError: For any database-related issues
        """
        try:
            self.validate_tokens(token,refresh_token)
            
            current_token = self.get_valid_token("access")
            current_refresh_token = self.get_valid_token("refresh")
            
            if not current_token or not current_refresh_token:
                logger.info("Existing tokens are invalid or missing. Creating new tokens.")
                self.clean_token("access" if current_token else "refresh")
                self.__create_token(token, refresh_token)
                return

            if current_token.token == token.token or current_refresh_token.token == token.token:
                logger.info("The token is already up to date.")
                return
                
            current_token.token, current_token.expires_at = self.encrypt(token.token), token.expires_at
            current_refresh_token.token, current_refresh_token.expires_at = self.encrypt(refresh_token.token), refresh_token.expires_at
            
            self.db.commit()
            logger.info("Tokens updated successfully.")
  
        except SQLAlchemyError as e:
            logger.error(f"Database error while updating tokens : {e}")
            self.db.rollback()
            raise TokenManagerError(str(e))
        except InvalidToken as e:
            logger.error(f"Failed to decrypt or encrypt token : {e}")
            raise 
        except Exception as e:
            logger.exception(f"Unknown error while updating tokens: {e}")
            raise

    def get_valid_token(self, token_type: str) -> Optional[TokenData]:
        """
        Retrieve a valid token of the specified type from the database.
        
        Args:
            token_type(str): Token type ('access' or 'refresh').
            
        Return:
            Optional[TokenData]: Valid token data or None if no valid token exists.
            
        Raises:
            SQLAlchemyError: For any database-related issues.
        """
        
        if token_type not in self.token_classes:
            raise ValueError(f"Invalid token type: {token_type}")
        
        token_class = self.token_classes[token_type]
        now = datetime.now(timezone.utc)
        
        try:
            token = self.db.query(token_class).populate_existing().first()
            if token:
                if token.expires_at <= now:
                    logger.info(f"{token_type.capitalize()} token has expired. Deleting it.")
                    try:
                        self.clean_token(token_type)
                        return None
                    except Exception:
                        self.db.rollback()  
                        logger.error(f"Failed to delete session with ")
                        
                token.token = self.decrypt(token.token)
                    
            logger.info(f"{token_type.capitalize()} token retrieved successfully.")
            
            return token
        except SQLAlchemyError as e:
            logger.error(f"Database error while retrieving {token_type} token: {e}")
            raise
        except InvalidToken as e:
            logger.error(f"Failed to decrypt session : {e}")
            raise 
        except Exception as e:
            logger.exception(f"Unknown error while retrieving {token_type} token: {e}")
            raise
        
    def clean_token(self, token_type: str) -> None:
        """
        Delete all tokens of the specified type from the database.
        
        Args:
            token_type(str): Token type ('access' or 'refresh').
            
        Raises:
            SQLAlchemyError: For any database-related issues.
        """
        
        if token_type not in self.token_classes:
            raise ValueError(f"Invalid token type: {token_type}")
        
        token_class = self.token_classes[token_type]
        
        try:
            self.db.query(token_class).delete()
            self.db.commit()
            logger.info(f"All {token_type} tokens deleted successfully.")
        except SQLAlchemyError as e:
            logger.error(f"Database error while deleting {token_type} tokens: {e}")
            return []
        except Exception as e:
            logger.exception(f"Unknown error while deleting {token_type} tokens: {e}")
            
    def get_all_tokens(self)-> dict:
        """
        Retrieve all access and refresh tokens from the database.
        
        Return:
            dict: Dictionary containing lists of access and refresh tokens.
        """
        try:
            access_tokens = self.db.query(TokenData).all()
            refresh_tokens = self.db.query(RefreshTokenData).all()
            
            for token in access_tokens:
                try:
                    token.token = self.decrypt(token.token)
                except InvalidToken as e:
                    logger.error(f"Failed to decrypt access token {token.id}: {e}")
                    raise ValueError(f"Invalid access token for token ID {token.id}.")
            
            for token in refresh_tokens:
                try:
                    token.token = self.decrypt(token.token)
                except InvalidToken as e:
                    logger.error(f"Failed to decrypt refresh token {token.id}: {e}")
                    raise ValueError(f"Invalid refresh token for token ID {token.id}.")
            
            logger.info("All tokens retrieved and decrypted successfully.")
            return {
            "access_tokens": [token.to_dict() for token in access_tokens],
            "refresh_tokens": [token.to_dict() for token in refresh_tokens]
            }
        
        except SQLAlchemyError as e:
            logger.error(f"Database error while retrieving tokens: {e}")
            raise
        except InvalidToken as e:
            logger.error(f"Failed to decrypt session : {e}")
            raise 
        except Exception as e:
            logger.exception(f"Unknown error while retrieving tokens: {e}")
            raise
