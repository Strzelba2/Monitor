from django.db.models.signals import Signal
from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver
from oauth2_provider.models import AccessToken
from userauth.utils import get_sessions_for_user
from typing import Any
import logging

logger = logging.getLogger('django')

redis_connection_failed = Signal()
redis_connected = Signal()

@receiver(post_delete, sender=AccessToken)
def logout_user_on_token_deletion(sender: type, instance: AccessToken, **kwargs: Any) -> None:
    """
    Logs out a user when their access token is deleted by invalidating their active sessions.

    Trigger:
        This function is triggered by the `post_delete` signal for the `AccessToken` model.

    Args:
        sender (type): The model class that sent the signal.
        instance (AccessToken): The deleted access token instance.
        **kwargs (Any): Additional keyword arguments provided by the signal.

    Logs:
        - Logs the deleted access token instance.
        - Logs each session key associated with the user being invalidated.
    """
    logger.info(f"Signal received: logout_user_on_token_deletion for instance: {instance}")

    user = instance.user 
    if user: 
        logger.info(f"Logging out user: {user} (User ID: {user.pk})")
        
        sessions = get_sessions_for_user(user)
        
        if not sessions:
            logger.info(f"No active sessions found for user {user}.")
            return
        
        for session in sessions:
            logger.info(f"Deleting session: {session.session_key}")
            session.delete()  
            
        logger.info("User successfully logged out due to token deletion.")
            
            
@receiver(pre_save, sender=AccessToken)
def prevent_multiple_access_tokens(sender: type, instance: AccessToken, **kwargs: Any) -> None:
    """
    Prevents the creation of multiple access tokens for the same user.

    Trigger:
        This function is triggered by the `pre_save` signal for the `AccessToken` model.

    Args:
        sender (type): The model class that sent the signal.
        instance (AccessToken): The access token instance being saved.
        **kwargs (Any): Additional keyword arguments provided by the signal.

    Raises:
        ValueError: If an access token already exists for the user.

    Logs:
        - Logs when a duplicate access token is detected and prevented.
    """
    logger.debug("Signal received: prevent_multiple_access_tokens.")
    if instance.pk is None:
        existing_token = AccessToken.objects.filter(user=instance.user).exists()
        
        if existing_token:
            logger.warning(f"Access token creation blocked for user {instance.user} (User ID: {instance.user.pk}).")
            raise ValueError("AccessToken already exists for this user. Cannot create a new one.") 
    else:
        logger.debug(f"Updating an existing access token: {instance.token}")


