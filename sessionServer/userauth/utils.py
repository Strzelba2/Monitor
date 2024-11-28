import logging
import redis
from .exceptions import *
from django.contrib.sessions.models import Session
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.auth.models import User
from typing import Set, Optional, Any
import redis

logger = logging.getLogger('django')

def get_sessions_for_user(user: User) -> list:
    """
    Retrieve all active sessions for a specific user.

    This function queries the session store to find sessions associated with the given user.

    Args:
        user (User): The user whose sessions are to be retrieved.

    Returns:
        list: A list of Session objects associated with the user.

    Logs:
        - Debug logs at the start and end of the function.
        - Logs errors if session data loading fails.
    """
    logger.debug("Starting session retrieval for user.")
    sessions = []
    
    # Retrieve all active sessions
    all_sessions = Session.objects.all()
    logger.debug(f"Found {len(all_sessions)} total active sessions.")
    
    for session in all_sessions:
        try:
            # Load session data from the session key
            session_data = SessionStore(session_key=session.session_key).load()
            logger.debug(f"Loaded session data for session key: {session.session_key}")
            
            # Check if the session belongs to the given user
            if session_data.get('_auth_user_id') == str(user.pk):
                logger.debug(f"Session key {session.session_key} belongs to user {user.pk}.")
                sessions.append(session)
        except Exception as e:
            # Handle errors like expired or corrupted sessions
            logger.error(
                f"Failed to load session data for session key {session.session_key}: {str(e)}"
            )
            
    logger.debug(f"Retrieved {len(sessions)} sessions for user {user.pk}.")
    return sessions

class AllowedUsersStore:
    """
    Singleton class for managing a set of allowed users in Redis.
    
    Attributes:
        _instance (Optional[AllowedUsersStore]): Singleton instance of the class.
        _redis_client (Optional[redis.Redis]): Redis client instance.
        _redis_key (str): Redis key for storing allowed users.
        _Redis_Connection (bool): Tracks the connection status to Redis.
    """
    _instance = None
    _redis_client = None
    _redis_key = "AllowedUsers"
    _Redis_Connection = False

    def __new__(cls):
        """
        Ensure the singleton behavior of the class.
        Initializes Redis on the first instantiation.
        """
        if cls._instance is None:
            cls._instance = super(AllowedUsersStore, cls).__new__(cls)
            cls._initialize_redis()
        return cls._instance

    @classmethod
    def check_redis_connection(cls) -> bool:
        """
        Check and maintain the Redis connection status.

        Returns:
            bool: True if Redis is connected; False otherwise.
        """
        logger.debug("Checking Redis connection.")
        try:
            if cls._redis_client:
                if not cls._redis_client.ping():
                    logger.warning("Redis connection lost.")
                    cls._redis_client = None
                    return False
            else:
                cls._redis_client = redis.Redis(host='redis', port=6379, db=0)
                if not cls._redis_client.ping():
                    logger.warning("Unable to connect to Redis.")
                    cls._redis_client = None
                    return False
                
            logger.info("Redis is connected.")
            return True
        except redis.ConnectionError as e:
            logger.error(f"Redis connection check failed: {e}")
            return False

        
    @classmethod
    def _initialize_redis(cls) -> None:
        """
        Initialize the Redis client and test the connection.
        Logs the connection status.
        """
        logger.debug("Initializing Redis connection.")
        try:
            cls._redis_client = redis.Redis(host='redis', port=6379, db=0)

            if not cls._redis_client.ping():
                raise redis.ConnectionError("Unable to reach Redis")
            
            logger.info("Redis initialized successfully.")
            cls._Redis_Connection = True
            
        except redis.ConnectionError as e:
            logger.error(f"Redis initialization failed: {e}")
            cls._redis_client = None
            cls._Redis_Connection = False  
            
    def redis_connected(self, connected: bool = True) -> None:
        """
        Update the Redis connection status.
        
        Args:
            connected (bool): Connection status to set.
        """
        logger.info(f"Updating Redis connection status to {connected}.")
        self._Redis_Connection = connected
        
    def check_if_redis_connected (self) -> bool:
        """
        Check and log the Redis connection status.
        
        Returns:
            bool: Current Redis connection status.
        """
        logger.info(f"Current Redis connection status: {self._Redis_Connection}.")
        return self._Redis_Connection
       
    def clear_allowed_users(self) -> None:
        """
        Clear all users from the allowed users set in Redis.
        """
        logger.debug("Clearing all allowed users in Redis.")
        if self._redis_client.exists("AllowedUsers"): 
            self._redis_client.srem("AllowedUsers", *self._redis_client.smembers("AllowedUsers"))    
            logger.info("Allowed users cleared successfully.")

    def get_allowed_users(self) -> Set[Any]:
        """
        Retrieve the set of allowed users from Redis.
        
        Returns:
            Set[Any]: The set of allowed users.
        
        Raises:
            RedisConnectionError: If Redis is unavailable.
        """
        logger.debug("Retrieving allowed users from Redis.")
        if self._redis_client:
            try:
                users = set(self._redis_client.smembers(self._redis_key))
                logger.info(f"Allowed users retrieved: {users}")
                return users
            except redis.ConnectionError as e:
                self._Redis_Connection = False
                logger.error(f"Failed to retrieve allowed users: {e}")
                raise RedisConnectionError("Redis connection failed.")

    def set_allowed_users(self, users: Set[Any]) -> None:
        """
        Replace the current allowed users set with a new set in Redis.
        
        Args:
            users (Set[Any]): A set of users to store in Redis.
        
        Raises:
            RedisConnectionError: If Redis is unavailable.
        """
        
        logger.debug(f"Setting allowed users in Redis: {users}")
        if self._redis_client:
            try:
                # Replace the existing set with a new one
                pipeline = self._redis_client.pipeline()
                pipeline.delete(self._redis_key)
                if users:
                    pipeline.sadd(self._redis_key, *users)
                pipeline.execute()
                logger.info("Allowed users updated successfully.")
            except redis.ConnectionError as e:
                self._Redis_Connection = False
                logger.error(f"Failed to set allowed users: {e}")
                raise RedisConnectionError("Redis connection failed.")

    def add_user(self, user: Any) -> None:
        """
        Add a single user to the allowed users set in Redis.
        
        Args:
            user (Any): The user to add.
        
        Raises:
            RedisConnectionError: If Redis is unavailable.
        """
        logger.debug(f"Adding user to allowed users in Redis: {user}")
        if self._redis_client:
            try:
                self._redis_client.sadd(self._redis_key, user)
                logger.info(f"User {user} added successfully.")
            except redis.ConnectionError:
                self._Redis_Connection = False
                logger.error("Failed to add a single user to the allowed users set in Redis.")
                raise RedisConnectionError("Redis connection failed.")

    def remove_user(self, user: Any) -> None:
        """
        Remove a single user from the allowed users set in Redis.
        
        Args:
            user (Any): The user to remove.
        
        Raises:
            RedisConnectionError: If Redis is unavailable.
        """
        
        logger.debug(f"Removing user from allowed users in Redis: {user}")
        if self._redis_client:
            try:
                self._redis_client.srem(self._redis_key, user)
                logger.info(f"User {user} removed successfully.")
            except redis.ConnectionError:
                self._Redis_Connection = False
                logger.error("Failed to remove a single user from the allowed users set in Redis.")
                raise RedisConnectionError("Redis connection failed.")
        
    def user_in_store(self, user: Any) -> bool:
        """
        Check if a user exists in the allowed users set in Redis.
        
        Args:
            user (Any): The user to check.
        
        Returns:
            bool: True if the user exists; False otherwise.
        
        Raises:
            RedisConnectionError: If Redis is unavailable.
        """
        
        logger.debug(f"Checking if user exists in Redis: {user}")
        if self._redis_client:
            try:
                exists = self._redis_client.sismember(self._redis_key, user)
                logger.info(f"User {user} existence: {exists}")
                return exists
            except redis.ConnectionError:
                self._Redis_Connection = False
                logger.error("Failed to check if a user is in the allowed users set..")
                raise RedisConnectionError("Redis connection failed.")
    