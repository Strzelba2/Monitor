import hmac
import hashlib
import base64
import logging

logger = logging.getLogger('django')

class HmacToken:
    """
    Utility class for generating and validating HMAC tokens.
    
    This class provides methods to calculate and verify HMAC signatures using a secret token 
    and a message. It ensures secure message authentication by preventing tampering.
    """
    @staticmethod
    def calculate_token(token:str, message:str) -> str:
        """
        Generates a Base64-encoded HMAC signature using SHA-256.

        Args:
            token (str): The secret key used for HMAC generation.
            message (str): The message to be signed.

        Returns:
            str: The Base64-encoded HMAC signature.
        """
        logger.debug(f"Calculating HMAC for message: {message}")
        
        hmac_signature = hmac.new(token.token.encode(), message.encode(), hashlib.sha256).hexdigest()

        # Encode the HMAC signature using Base64
        encoded_hmac_signature = base64.b64encode(hmac_signature.encode()).decode()
        
        logger.debug(f"Generated HMAC")
        return encoded_hmac_signature
    
    @staticmethod
    def is_valid_hmac(provided_hmac: str, token: str, message: str) -> bool:
        """
        Validates a provided HMAC signature against the expected signature.

        Args:
            provided_hmac (str): The HMAC signature provided for verification.
            token (str): The secret key used to generate the expected HMAC.
            message (str): The message that was signed.

        Returns:
            bool: True if the provided HMAC matches the expected HMAC, otherwise False.
        """
        expected_hmac = HmacToken.calculate_token(token, message)
        return hmac.compare_digest(provided_hmac, expected_hmac)
    
