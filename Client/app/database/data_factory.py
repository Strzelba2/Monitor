from .models import TokenData, RefreshTokenData
from datetime import datetime, timezone, timedelta
from typing import Tuple
import logging

logger = logging.getLogger(__name__)


def create_tokens(token_response: dict) -> Tuple[TokenData, RefreshTokenData]:
    """
    Create access and refresh tokens from the token response data.

    Args:
        token_response (dict): A dictionary containing token information.
            Required keys:
                - 'access_token': The access token string.
                - 'refresh_token': The refresh token string.
                - 'expires_in': The number of seconds until the tokens expire.

    Returns:
        Tuple[TokenData, RefreshTokenData]: A tuple containing access token and refresh token objects.

    Logs:
        - Logs the token creation process, including the expiration times.
    """
    
    now = datetime.now(timezone.utc)
    logger.info("Creating tokens using the provided token response.")

    # Create access token data
    access_token_data = TokenData(
        token=token_response['access_token'],
        expires_at=now + timedelta(seconds=token_response['expires_in'])
    )
    
    logger.debug(f"Access token created: ")

    # Create refresh token data
    refresh_token_data = RefreshTokenData(
        token=token_response['refresh_token'],
        expires_at=now + timedelta(seconds=token_response['expires_in'])
    )
    
    logger.debug(f"Refresh token created:")
    logger.info("Token creation process completed.")
    
    return access_token_data , refresh_token_data
