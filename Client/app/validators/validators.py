import logging
import re

logger = logging.getLogger(__name__)

class LoginValidator:

    @staticmethod
    def password_validate(password: str) -> None:
        """
        Validate a password against predefined strength rules.

        Args:
            password (str): The password to validate.

        Raises:
            ValueError: If the password fails any of the strength checks.
        """
        logger.debug("Validating password for strength requirements.")
        
        if len(password) < 12:
            logger.error("Password validation failed: too short.")
            raise ValueError(
                "Password must be at least 12 characters long."
            )
        if not re.search(r"[A-Z]", password):
            logger.error("Password validation failed: missing uppercase letter.")
            raise ValueError(
                "Password must contain at least one uppercase letter."
            )
        if not re.search(r"[a-z]", password):
            logger.error("Password validation failed: missing lowercase letter.")
            raise ValueError(
                "Password must contain at least one lowercase letter."
            )
        if not re.search(r"[0-9]", password):
            logger.error("Password validation failed: missing digit.")
            raise ValueError(
                "Password must contain at least one digit."
            )
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            logger.error("Password validation failed: missing special character.")
            raise ValueError(
                "Password must contain at least one special character."
            )
        
        logger.info("Password passed all strength validation checks.")
     
    @staticmethod   
    def username_validate(username: str) -> None:
        """
        Validates the username to ensure it meets specific character requirements.
        Allows only letters, numbers, dots, +, and hyphens.
        
        Args:
            username(str): The username to validate.
        Raises:
            ValueError: If the username does not meet the required format.
        """
        regex = r"^[\w.+-]+\Z"
        if not re.match(regex, username):
            raise ValueError(
                "Username is not valid. A username can only contain letters, numbers, a dot, + symbol, and a hyphen."
            )
    @staticmethod          
    def code_2fa_validate(code_2fa: str) -> None:
        """
        Validates the 2FA code to ensure it consists only of digits and is exactly 6 characters long.

        Args:
            code_2fa(str): The 2FA code to validate.
            
        Raises:
            ValueError: If the 2FA code is invalid.
        """
        if not code_2fa.isdigit() or len(code_2fa) != 6:
            raise ValueError("2FA code must consist of exactly 6 digits.")

