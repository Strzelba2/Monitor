from django.core.exceptions import ValidationError
from django.core import validators
from django.utils.translation import gettext as _
import re

import logging

logger = logging.getLogger("django")

def validate_signed_token_format(token: str, min_length=10, max_length=255) -> None:
    """
    Validates that a token:
    - Contains only valid characters: letters, numbers, '-', '_', ':', and '.'.
    - Includes a ':' separating the signed value and the hash.
    - Has a length within the specified range.
    """
    # Check length
    if not (min_length <= len(token) <= max_length):
        raise ValidationError(
            _(f"Token must be between {min_length} and {max_length} characters long."),
            code='invalid_token_length',
        )

    # Check characters
    if not re.fullmatch(r'^[A-Za-z0-9_\-:]+$', token):
        raise ValidationError(
            _("Token must contain only valid characters: letters, numbers, '-', '_', and ':'"),
            code='invalid_token_format',
        )

    # Check structure
    if ':' not in token:
        raise ValidationError(
            _("Token must include a ':' separating the value and the hash."),
            code='invalid_token_structure',
        )

class CustomPasswordValidator:
    """
    A custom password validator that enforces strong password requirements.

    The password must:
    - Be at least 12 characters long.
    - Contain at least one uppercase letter.
    - Contain at least one lowercase letter.
    - Contain at least one digit.
    - Contain at least one special character from the set: !@#$%^&*(),.?":{}|<>.
    """
    def validate(self, password: str, user=None) -> None:
        """
        Validate a password against predefined strength rules.

        Args:
            password (str): The password to validate.
            user: The user associated with the password (default is None).

        Raises:
            ValidationError: If the password fails any of the strength checks.
        """
        logger.debug("Validating password for strength requirements.")
        
        if len(password) < 12:
            logger.error("Password validation failed: too short.")
            raise ValidationError(
                _("Password must be at least 12 characters long.")
            )
        if not re.search(r"[A-Z]", password):
            logger.error("Password validation failed: missing uppercase letter.")
            raise ValidationError(
                _("Password must contain at least one uppercase letter.")
            )
        if not re.search(r"[a-z]", password):
            logger.error("Password validation failed: missing lowercase letter.")
            raise ValidationError(
                _("Password must contain at least one lowercase letter.")
            )
        if not re.search(r"[0-9]", password):
            logger.error("Password validation failed: missing digit.")
            raise ValidationError(
                _("Password must contain at least one digit.")
            )
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            logger.error("Password validation failed: missing special character.")
            raise ValidationError(
                _("Password must contain at least one special character.")
            )
        
        logger.info("Password passed all strength validation checks.")

    def get_help_text(self) -> str:
        """
        Provide a help text describing the password requirements.

        Returns:
            str: A description of the password requirements.
        """
        logger.debug("Retrieving password help text.")
        return _(
            "Your password must be at least 12 characters long, "
            "contain at least one uppercase letter, one lowercase letter, "
            "one digit, and one special character."
        )
        
class UsernameValidator(validators.RegexValidator):
    """
    Validator for the username field, ensuring it meets specific character requirements.
    Allows only letters, numbers, dots, @, +, and hyphens.
    """
    regex = r"^[\w.+-]+\Z"
    message = _(
        "username is not valid. A username can only contain letters, numbers, a dot, "
        " + symbol and a hyphen "
    )
