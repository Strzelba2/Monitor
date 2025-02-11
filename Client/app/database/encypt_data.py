from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)

class SharedKeyCipher:
    """
    Singleton class for managing a shared encryption key and cipher using Fernet encryption.

    This class ensures that all parts of the application use a consistent encryption key.
    It provides methods to set, retrieve, and clear the key while maintaining a singleton instance.

    Attributes:
        _instance (SharedKeyCipher): Singleton instance of the class.
        _initialized (bool): Flag to track whether the instance has been initialized.
    """
    _instance = None
    _initialized = False
    
    def __new__(cls, *args, **kwargs):
        """
        Implements the Singleton pattern to ensure only one instance of SharedKeyCipher exists.

        Returns:
            SharedKeyCipher: The singleton instance.
        """
        if not cls._instance:
            cls._instance = super().__new__(cls, *args, **kwargs)
            logger.info("SharedKeyCipher instance created successfully.")
        return cls._instance
    
    def __init__(self):
        """
        Initializes the shared key and cipher state. 

        Ensures that the class is initialized only once.
        """
        if not self._initialized:
            logger.info("Initializing SharedKeyCipher for the first time.")
            self._key = None
            self._cipher = None
            SharedKeyCipher._initialized = True
            logger.info("SharedKeyCipher initialized successfully.")
        
    @property
    def key(self) -> bytes:
        """
        Get the shared encryption key.

        Returns:
            bytes: The stored encryption key.

        Raises:
            ValueError: If the key has not been set.
        """
        if self._key is None:
            logger.warning("Attempted to access encryption key before it was set.")
            raise ValueError("Encryption key has not been set.")
        logger.debug("Returning encryption key.")
        return self._key
    
    @property
    def cipher(self) -> Fernet:
        """
        Get the shared encryption cipher.

        Returns:
            Fernet: The Fernet cipher instance for encryption.

        Raises:
            ValueError: If the cipher has not been initialized.
        """
        if self._cipher is None:
            logger.warning("Attempted to access cipher before key was set.")
            raise ValueError("Cipher has not been initialized.")
        logger.debug("Returning shared encryption cipher.")
        return self._cipher
    
    @key.setter
    def key(self, key: bytes) -> None:
        """
        Set the shared encryption key and initialize the Fernet cipher.

        Args:
            key (bytes): The encryption key.
        """
        self._key = key
        self._cipher = Fernet(key)
        logger.info("Shared key and cipher updated in singleton.")
        
    def clear(self) -> None:
        """
        Clear the shared encryption key and cipher, resetting the singleton state.

        This is useful for re-initializing the encryption settings securely.
        """
        self._key = None
        self._cipher = None
        logger.info("Shared encryption state cleared successfully.")
    
        