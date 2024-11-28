from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from .validators import UsernameValidator
from .managers import UserManager
from .signals import redis_connection_failed, redis_connected
from .exceptions import * 
from .utils import AllowedUsersStore 
import os

import logging

logger = logging.getLogger('django')


    
class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.
    
    Attributes:
        first_name (CharField): The user's first name.
        last_name (CharField): The user's last name.
        email (EmailField): The user's unique email address.
        username (CharField): The user's unique username, validated with UsernameValidator.
        allowed_users (AllowedUsersStore): Stores allowed users in Redis.
    """
    
    logger.info(f"User class loaded in process PID: {os.getpid()}")

    first_name = models.CharField(verbose_name=_("First Name"), max_length=60)
    last_name = models.CharField(verbose_name=_("Last Name"), max_length=60)
    email = models.EmailField(
        verbose_name=_("Email Address"), unique=True, db_index=True
    )
    username = models.CharField(
        verbose_name=_("Username"),
        max_length=60,
        unique=True,
        validators=[UsernameValidator()],
    )

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = ["username", "first_name", "last_name"]

    objects = UserManager()
    allowed_users = AllowedUsersStore()
    
    class Meta:
        """
        Meta options for the User model.
        
        Attributes:
            verbose_name (str): The singular name for the User model in the admin interface.
            verbose_name_plural (str): The plural name for the User model in the admin interface.
            ordering (list): Default ordering for User instances, by date joined in descending order.
        """
        verbose_name = _("User")
        verbose_name_plural = _("Users")
        ordering = ["-date_joined"]
        
    def __str__(self) -> str:
        """
        Returns the string representation of the User instance, which is the username.
        
        Returns:
            str: The username of the user.
        """
        return self.username
    
    def save(self, *args, **kwargs) -> None:
        """
        Custom save method that updates allowed_users in Redis upon username change.
        
        Parameters:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
            
        Logs the addition of users and handles potential Redis connection issues.
        """
        # Check if the username is changing
        if self.pk: 
            old_username = User.objects.get(pk=self.pk).username
            if old_username != self.username:
                # Remove the old username and add the new one
                self.remove_allowed_user(old_username)
                logger.debug(f"Removing old username '{old_username}' from allowed_users.")

        # Call the original save method
        super().save(*args, **kwargs)

        # After saving, add the current username to allowed_users
        self.add_allowed_user(self.username)
        
        logger.debug(f"Added '{self.username}' to allowed_users. Current users: {User.allowed_users.get_allowed_users()}")

    @classmethod
    def clear_allowed_users(cls) -> None:
        
        if cls.allowed_users.check_if_redis_connected():
            try:
                cls.allowed_users.clear_allowed_users()

            except RedisConnectionError as e:
                cls.allowed_users.redis_connected(False) 
                logger.error("Redis connection failed while adding allowed user.", exc_info=e)
                
        
    
    @classmethod
    def load_allowed_users(cls) -> None:
        """
        Loads all active users into allowed_users from the database when Redis is connected.
        """
        logger.debug("Starting to load allowed users from database to Redis.")
        if cls.allowed_users.check_if_redis_connected():
            try:
                users = cls.objects.filter(is_active=True).values_list('username', flat=True)
                cls.allowed_users.set_allowed_users(users)
                logger.debug("Allowed users loaded successfully into Redis.")
            except RedisConnectionError as e:
                cls.allowed_users.redis_connected(False)
                logger.error("Redis connection failed during load_allowed_users.", exc_info=e)
                
        
        
    @classmethod
    def add_allowed_user(cls, username) -> None:
        """
        Adds a username to the allowed_users list in Redis.
        
        Parameters:
            username (str): The username to add to allowed_users.
            
        If the connection fails, logs an error and sets Redis_Connection to False.
        """
        if cls.allowed_users.check_if_redis_connected():
            try:
                cls.allowed_users.add_user(username)
                logger.debug(f"User '{username}' added to allowed_users in Redis.")
            except RedisConnectionError as e:
                cls.allowed_users.redis_connected(False)
                logger.error("Redis connection failed while adding allowed user.", exc_info=e)
        
    @classmethod
    def remove_allowed_user(cls, username) -> None:
        """
        Removes a username from the allowed_users list in Redis.
        
        Parameters:
            username (str): The username to remove from allowed_users.
            
        If the connection fails, logs an error and sets Redis_Connection to False.
        """
        if cls.allowed_users.check_if_redis_connected():
            try:
                cls.allowed_users.remove_user(username) 
                logger.debug(f"User '{username}' removed from allowed_users in Redis.")
            except RedisConnectionError as e:
                cls.allowed_users.redis_connected(False)
                logger.error("Redis connection failed while removing allowed user.", exc_info=e)
                
        
    @classmethod
    def is_user_allowed(cls, username) -> bool:
        """
        Checks if a user is in the allowed_users list in Redis.
        
        Parameters:
            username (str): The username to check.
        
        Returns:
            bool: True if the user is allowed, False otherwise.
            
        Falls back to the database if Redis is not connected.
        """
        
        logger.info(f"is_user_allowed in process PID: {os.getpid()}:" \
                    f"redis Connection {cls.allowed_users.check_if_redis_connected()}")
        if cls.allowed_users.check_if_redis_connected():
            logger.debug(f"Connection with redit successful")
            try:
                if not cls.allowed_users.get_allowed_users():
                    logger.debug("Allowed users list is empty")
                    cls.load_allowed_users()
                    
                is_allowed = cls.allowed_users.user_in_store(username)
                logger.debug(f"User '{username}' is {'allowed' if is_allowed else 'not allowed'} in Redis.")
                return is_allowed
            except RedisConnectionError as e:
                cls.allowed_users.redis_connected(False)
                logger.error("Redis connection failed during is_user_allowed check.", exc_info=e)
                return username in list(cls.objects.filter(is_active=True).values_list('username', flat=True))
        else:
            logger.debug(f"no connection with redis")
            return username in list(cls.objects.filter(is_active=True).values_list('username', flat=True))
                

    @property
    def get_full_name(self) -> str:
        """
        Returns the full name of the user.
        
        Returns:
            str: The full name of the user, which combines the first and last names.
        """
        full_name = f"{self.first_name} {self.last_name}"
        return full_name.strip()
  
# Signal receivers for Redis connection and user deletion  
@receiver(post_delete, sender=User)
def update_allowed_users_on_delete(sender, instance, **kwargs) -> None:
    """
    Removes the user from allowed_users in Redis when they are deleted from the database.
    
    Parameters:
        sender: The model class.
        instance: The instance being deleted.
        **kwargs: Additional keyword arguments.
    """
    logger.debug(f"User '{instance.username}' is being deleted. Updating allowed_users.")
    User.remove_allowed_user(instance.username)
    
@receiver(redis_connection_failed)
def handle_redis_connection_failed(sender, **kwargs)-> None:
    """
    Sets Redis_Connection to False on Redis connection failure.
    
    Parameters:
        sender: The sender of the signal.
        **kwargs: Additional keyword arguments.
    """
    logger.warning("Redis connection failed. Disabling Redis-based user checks.")
    User.allowed_users.redis_connected(False)
    
@receiver(redis_connected)
def handle_redis_connected(sender, **kwargs) -> None:
    """
    Handles successful Redis connection, setting Redis_Connection to True and loading allowed users.
    
    Parameters:
        sender: The sender of the signal.
        **kwargs: Additional keyword arguments.
    """
    logger.info(f"Redis connected successfully.in process PID: {os.getpid()} from {sender}")
    logger.info(f"check: { User.allowed_users.check_if_redis_connected()} ")
    if not User.allowed_users.check_if_redis_connected():
        logger.info(f"User.Redis_Connection False.in process PID: {os.getpid()}")
        User.allowed_users.redis_connected(True)
        User.load_allowed_users()
        
class UsedToken(models.Model):
    token = models.CharField(
        verbose_name=_("Token"),
        max_length=255,
        unique=True,
        editable=False,
        help_text=_("The unique token associated with the user."),
    )
    user = models.ForeignKey(
        User,
        verbose_name=_("User"),
        on_delete=models.CASCADE,
        editable=False,
        help_text=_("The user who used this token."),
    )
    used_at = models.DateTimeField(
        verbose_name=_("Used At"),
        auto_now_add=True,
        editable=False,
        help_text=_("The timestamp when this token was used."),
    )

    def __str__(self):
        return f"Token for {self.user.username} used at {self.used_at}"

    class Meta:
        verbose_name = _("Used Token")
        verbose_name_plural = _("Used Tokens")
        ordering = ["-used_at"]
        