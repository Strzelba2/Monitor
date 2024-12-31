# from PyQt6.QtCore import QObject

from app.database.token_db_manager import TokenDManager
from .refresh_token import RefreshTokenManager
from sqlalchemy.exc import  SQLAlchemyError
from app.exceptions.database_exc import TokenDBManagerError
from app.database.data_factory import create_tokens

import logging


logger = logging.getLogger(__name__)

class TokenManager():
    
    def __init__(self):
        """
        Initialize the TokenManager class.

        Attributes:
            _token_db_manager (TokenDManager): Manager for token database operations.
            _refresh_token (RefreshTokenManager): Manager for token refresh operations.
        """
        self._token_db_manager = TokenDManager()
        self._refresh_token = RefreshTokenManager()
        
    def generate_secret_key(self, code_2fa: str, password: str) -> None:
        """
        Generates a secret key using 2FA code and password.
        
        Args:
            code_2fa(str): Two-factor authentication code.
            password(str): User's password.
            
        Raise:
            ValueError: If code_2fa or password is invalid.
            Exception: For other unexpected errors.
        """
        try:
            # Validate input
            if not code_2fa or not isinstance(code_2fa, str) or len(code_2fa.strip()) == 0:
                logger.error("Invalid 2FA code provided.")
                raise ValueError("2FA code cannot be empty and must be a non-empty string.")

            if not password or not isinstance(password, str) or len(password.strip()) == 0:
                logger.error("Invalid password provided.")
                raise ValueError("Password cannot be empty and must be a non-empty string.")

            logger.debug("Validating inputs for secret key generation.")
            logger.info(f"Attempting to generate secret key using 2FA code of length {len(code_2fa)} and password.")

            # Call the TokenDManager method to generate the key
            self._token_db_manager.generate_secret_key(code_2fa, password)

            logger.info("Secret key generated successfully.")
        except ValueError as ve:
            logger.error(f"Validation error during secret key generation: {ve}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during secret key generation: {e}")
            raise
        
    def clear_secret_key(self) -> None:
        """
        Clears the secret key from the token database manager.

        Raises:
            ValueError: If the token database manager is not initialized.
            Exception: For other unexpected errors.
        """
        try:
            if not self._token_db_manager:
                raise ValueError("Token database manager is not initialized.")
            
            self._token_db_manager.cipher = None
            self._token_db_manager.key = None
            logger.info("Secret key cleared.")
        except AttributeError as e:
            logger.error(f"Failed to clear secret key: Token database manager attributes are missing. {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error while clearing secret key: {e}")
            raise

    async def save_token(self, token_data: dict) -> None:
        """
        Creates and saves access and refresh tokens based on the provided token data.

        Args:
            token_data(dict): Data used to generate tokens.

        Raises:
            ValueError: If the token data is invalid or malformed.
            TokenDBManagerError: If there is a database error during token saving.
        """
        logger.info("Starting the token save process.")
        try:
            # Generate tokens
            access_token , refresh_token = create_tokens(token_data)
            logger.info("Tokens data created successfully")
            
            await self._token_db_manager.update_tokens(access_token,refresh_token)
            logger.info("Tokens saved successfully.")
        except KeyError as e:
            logger.error(f"Token response missing required key: {e}")
            raise ValueError("Invalid token data format.") from e
        except TokenDBManagerError as e:
            logger.error(f"Failed to update tokens in the database: {e}")
            raise  
        except Exception as e:
            logger.error(f"Unexpected error while saving tokens: {e}")
            raise

    async def get_token_access_token(self):
        """
        Retrieve the access token.

        Returns:
            TokenData: Valid access token or None if no valid token exists.
        
        Raises:
            ValueError: If token type is invalid.
            SQLAlchemyError: For database-related errors.
            Exception: For unexpected errors.
        """
        try:
            access_token = self._token_db_manager.get_valid_token("access")
            return access_token
        except ValueError as e:
            logger.error(f"Invalid token type requested: {e}")
            raise
        except SQLAlchemyError as e:
            logger.error(f"Database error while retrieving access token: {e}")
            raise
        except Exception as e:
            logger.exception(f"Unexpected error while retrieving access token: {e}")
            raise
        
    async def get_all_tokens(self)-> dict[str, list[dict]]:
        """
        Retrieve all tokens from the database through the token manager.

        Returns:
            dict: Dictionary containing decrypted access and refresh tokens.

        Raises:
            Exception: For any issues while retrieving tokens.
        """
        logger.info("get_all_tokens processed")
        try:
            tokens = await self._token_db_manager.get_all_tokens()
            return tokens
        except Exception as e:
            logger.exception(f"Failed to retrieve tokens via token manager: {e}")
            raise
        
    async def clear_tokens(self) -> None:
        """
        Clear all access and refresh tokens from the database.
        Logs success or failure for each token type.
        """
        for token_type in ["access", "refresh"]:
            try:
                await self._token_db_manager.clear_token(token_type)
                logger.info(f"Successfully cleared {token_type} tokens.")
            except ValueError as e:
                logger.error(f"Invalid token type provided: {token_type}. Error: {e}")
            except Exception as e:
                logger.exception(f"Failed to clear {token_type} tokens: {e}")
        
    def start_refresh_timer(self,refresh_interval: int = 8400) -> None:
        """
        Start the token refresh timer.

        Args:
            refresh_interval (int): Time interval in seconds for refreshing tokens. Defaults to 8400 seconds.
        
        Raises:
            RuntimeError: If the refresh timer is already running.
        """
        try:
            self._refresh_token.start(refresh_interval)
            logger.info(f"Token refresh timer started with interval: {refresh_interval} seconds.")
        except RuntimeError as e:
            logger.error(f"Failed to start refresh timer: {e}")
            raise
        except Exception as e:
            logger.exception(f"Unexpected error while starting refresh timer: {e}")
            raise
        
    def stop_refresh_timer(self) -> None:
        """
        Stop the token refresh timer.

        Logs the success or failure of the operation.
        """
        try:
            self._refresh_token.stop()
            logger.info("Token refresh timer stopped successfully.")
        except Exception as e:
            logger.exception(f"Unexpected error while stopping refresh timer: {e}")
            raise