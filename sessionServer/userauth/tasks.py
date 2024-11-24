from celery import shared_task
from .utils import AllowedUsersStore
from oauth2_provider.models import AccessToken, RefreshToken
from django.utils import timezone
from .signals import *

import logging

logger = logging.getLogger('django')


@shared_task(name="monitor_redis_connection")
def monitor_redis_connection() -> None:
    """
    Monitors the Redis connection and sends appropriate signals based on the connection status.

    If the connection is active, it sends the `redis_connected` signal.
    Otherwise, it sends the `redis_connection_failed` signal.
    """
    logger.info("Starting task: monitor_redis_connection.")
    try:
        if AllowedUsersStore.check_redis_connection():
            logger.info("Redis connection is active. Sending `redis_connected` signal.")
            redis_connected.send(sender=monitor_redis_connection)
        else:
            logger.warning("Redis connection is inactive. Sending `redis_connection_failed` signal.")
            redis_connection_failed.send(sender=monitor_redis_connection)
    except Exception as e:
        logger.error(f"An error occurred while monitoring Redis connection: {e}", exc_info=True)
        
@shared_task(name="delete_expired_tokens")    
def delete_expired_tokens()-> None:
    """
    Deletes expired access tokens and any orphaned refresh tokens.

    - Removes all access tokens with an expiry date in the past.
    - Removes refresh tokens associated with deleted access tokens.
    """
    logger.info("Starting task: delete_expired_tokens.")
    
    try:
        # Delete expired access tokens
        expired_access_tokens = AccessToken.objects.filter(expires__lt=timezone.now())
        deleted_access_tokens_count = expired_access_tokens.count()
        expired_access_tokens.delete()
        logger.info(f"Deleted {deleted_access_tokens_count} expired access tokens.")

        # Delete orphaned refresh tokens
        orphaned_refresh_tokens = RefreshToken.objects.filter(access_token__isnull=True)
        deleted_refresh_tokens_count = orphaned_refresh_tokens.count()
        orphaned_refresh_tokens.delete()
        logger.info(f"Deleted {deleted_refresh_tokens_count} orphaned refresh tokens.")
    except Exception as e:
        logger.error(f"An error occurred while deleting expired tokens: {e}", exc_info=True)
        

