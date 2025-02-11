import hashlib
import base64
from cryptography.fernet import Fernet
from .encypt_data import SharedKeyCipher
import logging

logger = logging.getLogger(__name__)

class SingletonMeta(type):
    """
    A metaclass for creating Singleton classes. Ensures only one instance of a class exists.
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            logger.debug(f"Creating a new instance of {cls.__name__}.")
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]
    
class BaseManager:
    """
    A base manager class for managing encryption and decryption using Fernet symmetric encryption.
    """
    def __init__(self):
        """
        Initializes the BaseManager instance.

        This constructor sets up encryption management using `SharedKeyCipher` but 
        does not initialize it with a secret key or cipher, leaving it in an unconfigured state.
        """
        self.encryt_data = SharedKeyCipher()

        logger.info("BaseManager instance created. Encryption handler initialized but not configured with a secret key.")
        
    @property
    def cipher(self):
        return self.encryt_data.cipher

    def generate_secret_key(self, code_2fa: str, password: str) -> None:
        """
        Generate and store a secret key using a 2FA code and a password.
        
        Args:
            code_2fa (str): The two-factor authentication code.
            password (str): The user's password.

        Returns:
            None
        """
        logger.debug("Generating secret key from 2FA code and password.")
        
        # Combine 2FA code and password into key material
        key_material = (code_2fa + password).encode('utf-8')
        logger.debug("Key material generated.")

        # Generate a SHA-256 hash of the key material
        sha256_hash = hashlib.sha256(key_material).digest()
        logger.debug("SHA-256 hash generated for key material.")
        
        self.encryt_data.key = base64.urlsafe_b64encode(sha256_hash[:32])
        logger.info("Encryption key successfully generated and stored in Fernet cipher.")

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string.
        
        Args:
            plaintext (str): The text to encrypt.

        Returns:
            str: The encrypted string.

        Raises:
            ValueError: If the cipher is not initialized.
        """
        if not self.cipher:
            logger.error("Cipher not initialized. Call generate_secret_key() first.")
            raise ValueError("Cipher not initialized. Call generate_secret_key() first.")
        
        logger.info("Encryption successful.")
        return self.cipher.encrypt(plaintext.encode()).decode()

    def decrypt(self, encrypted: str) -> str:
        """
        Decrypt an encrypted string.
        
        Args:
            encrypted (str): The encrypted text to decrypt.

        Returns:
            str: The decrypted string.

        Raises:
            ValueError: If the cipher is not initialized.
        """
        logger.debug(f"Decrypting encrypted text: {encrypted}")
        
        if not self.cipher:
            logger.error("Cipher not initialized. Call generate_secret_key() first.")
            raise ValueError("Cipher not initialized. Call generate_secret_key() first.")
        
        logger.info("Decryption successful.")
        return self.cipher.decrypt(encrypted.encode()).decode()