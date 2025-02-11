from django.db import models
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import timedelta
import secrets
import re
import uuid
from .validators import *
import json

logger = logging.getLogger('django')

def get_default_blocked_until():
    """
    Returns the default time for which an IP address should be blocked.

    This function sets the default blocked duration to 1200 seconds (20 minutes)
    from the current time.
    """
    return timezone.now() + timedelta(seconds=1200)

class BlockedIP(models.Model):
    """
    Represents an IP address that has been blocked from accessing the system.

    This model stores information about IP addresses that have been blocked due
    to suspicious activity or exceeding access attempts.
    """
    
    ip_address = models.CharField(
        verbose_name=_("IP Adress"),
        max_length=255, 
        unique=True, 
        validators=[validate_ip_address_with_port],
        help_text="The IP address that is being blocked."
    )
    blocked_until = models.DateTimeField(
        verbose_name=_("Block Until"),
        default=get_default_blocked_until,
        validators=[validate_blocked_until],
        help_text="The time until which the IP address will remain blocked."
    )
    path = models.CharField(
        verbose_name=_("Path"),
        max_length=255,
        default="/default",
        help_text="The path associated with the blocked IP address (optional)."
    )
    user_agent = models.CharField(
        verbose_name=_("User Agent"),
        max_length=255,
        default='',
        blank=True,
        null=True,
        help_text="The user agent string associated with the blocked IP address (optional)."
    )
    timestamp = models.DateTimeField(default=timezone.now)
    
    def save(self, *args, **kwargs):
        """
        Validates and saves the BlockedIP object.

        This method performs additional validation on data types and truncates
        fields exceeding the maximum length before saving the object.
        """
        # Validate data types
        if self.ip_address is not None and not isinstance(self.ip_address, str):
            raise ValidationError("ip_address must be a string")
        if self.path is not None and not isinstance(self.path, str):
            raise ValidationError("path must be a string")
        if self.user_agent is not None and not isinstance(self.user_agent, str):
            raise ValidationError("user_agent must be a string")

        # Trim fields to max_length
        if len(self.path) > 255:
            self.path = self.path[:255]
        if self.user_agent and len(self.user_agent) > 255:
            self.user_agent = self.user_agent[:255]
            
        self.full_clean() 
            
        super().save(*args, **kwargs)

    def __str__(self):
        """
        Returns a string representation of the BlockedIP object.

        The string representation includes the IP address of the blocked IP.
        """
        return self.ip_address
    
    class Meta:
        verbose_name = _("Blocked IP Address")
        verbose_name_plural = _("Blocked IP Address")
        ordering = ["-ip_address"]
    
class RequestLog(models.Model):
    """
    Represents a log entry for a request made to the system.

    Stores information about incoming requests, including the path, HTTP method,
    IP address, user agent, and timestamp.
    """
    
    path = models.CharField(
        verbose_name=_("Path"),
        max_length=255,
        blank=True,
        null=True,
        help_text="The URL path of the requested resource."
    )
    method = models.CharField(
        verbose_name=_("Method"),
        max_length=10,
        blank=True,
        null=True,
        help_text="The HTTP method used for the request (e.g., GET, POST, PUT)."
    )
    ip_address = models.CharField(
        verbose_name=_("IP Adress"),
        max_length=45,
        blank=True,
        null=True,
        help_text="The IP address of the client making the request."
    )
    user_agent = models.CharField(
        verbose_name=_("User Agent"),
        max_length=255,
        blank=True,
        null=True,
        help_text="The user agent string sent by the client's browser."
    )
    timestamp = models.DateTimeField(
        verbose_name=_("Timestamp"),
        auto_now_add=True,
        blank=True,
        null=True,
        help_text="The timestamp when the request was received."
    )
    
    def save(self, *args, **kwargs):
        """
        Validates and saves the RequestLog object.

        Ensures that data types are correct, trims fields to their maximum length,
        and performs full model validation before saving.
        """
        # Validate data types
        if self.path is not None and not isinstance(self.path, str):
            raise ValidationError("path must be a string")
        if self.method is not None and not isinstance(self.method, str):
            raise ValidationError("method must be a string")
        if self.ip_address is not None and not isinstance(self.ip_address, str):
            raise ValidationError("ip_address must be a string")
        if self.user_agent is not None and not isinstance(self.user_agent, str):
            raise ValidationError("user_agent must be a string")

        # Trim fields to max_length
        if self.path and len(self.path) > 255:
            self.path = self.path[:255]
        if self.method and len(self.method) > 10:
            self.method = self.method[:10]
        if self.ip_address and len(self.ip_address) > 45:
            self.ip_address = self.ip_address[:45]
        if self.user_agent and len(self.user_agent) > 255:
            self.user_agent = self.user_agent[:255]
            
        self.full_clean()
        
        super().save(*args, **kwargs)

    def __str__(self):
        """
        Returns a string representation of the RequestLog object.

        The string representation includes the HTTP method, path, IP address, and timestamp of the request.
        """
        return f"{self.method} {self.path} from {self.ip_address} at {self.timestamp}"
    
    class Meta:
        verbose_name = _("Requests logs")
        verbose_name_plural = _("Requests logs")
        ordering = ["-ip_address"]
    
class Server(models.Model):
    """
    Represents a server in your system.

    This model stores information about servers used in your application,
    including their name, IP address, port, location, assigned user, and
    trust and availability status.
    """
    
    name = models.CharField(
        verbose_name=_("Server Name"),
        max_length=100,
        unique=True,
        blank=False,
        help_text="The name of the server."
    )
    ip_address = models.GenericIPAddressField(
        verbose_name=_("IP Adress"),
        unique=True,
        blank=False,
        help_text="The IP address of the server."
    )
    port = models.IntegerField(
        verbose_name=_("Port"),
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
        help_text="The port number of the server."
    )
    location = models.CharField(
        verbose_name=_("Server Location"),
        max_length=100,
        help_text="The location of the server."
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        help_text="The user associated with the server (optional).",
        verbose_name=_("User")
    )
    trusty = models.BooleanField(
        verbose_name=_("If Trust"),
        default=False,
        help_text="Indicates whether the server is trusted."
    )
    available = models.BooleanField(
        verbose_name=_("If Available"),
        default=False,
        help_text="Indicates whether the server is available."
    )
    screens = models.IntegerField(
        verbose_name=_("Screens"),
        default=1,
        help_text="Indicates how many screens server have."
    )
    
    def clean(self):
        """
        Performs additional validation on server data before saving.

        Ensures that required fields (`name`, `location`, and `ip_address`)
        are not empty and raises validation errors if any are missing.
        """
        super().clean()

        if not self.name:
            raise ValidationError("The 'name' field cannot be empty.")
        
        if not self.location:
            raise ValidationError("The 'location' field cannot be empty.")
        
        if not self.ip_address:
            raise ValidationError("The 'ip_address' field cannot be empty.")
        
    def save(self, *args, **kwargs):
        """
        Validates and saves the Server object.

        Ensures that data types are correct, trims fields exceeding maximum length,
        and performs full model validation before saving.
        """

        if self.name is not None and not isinstance(self.name, str):
            raise ValidationError("name must be a string")
        
        if self.location is not None and not isinstance(self.location, str):
            raise ValidationError("location must be a string")
        
        if self.name and len(self.name) > 100:
            self.name = self.name[:100]
        if self.location and len(self.location) > 100:
            self.location = self.location[:100]
            
        self.full_clean()
        
        super().save(*args, **kwargs)

    def __str__(self):
        """
        Returns a string representation of the Server object.

        The string representation includes the server name.
        """
        return self.name
    
    class Meta:
        verbose_name = _("Server")
        verbose_name_plural = _("Server")
        ordering = ["-name"]

def get_expiry_time_session():
    return timezone.now() + timedelta(hours=settings.MAX_EXPIRATION_HOURS)
    
class Session(models.Model):
    """
    Represents a user session within the system.

    This model stores information about user sessions, including the
    associated user, unique session ID, server where the session is active,
    expiration time, creation time, and validation checks.
    """
    
    MIN_EXPIRATION = settings.MIN_EXPIRATION_HOURS 
    MAX_EXPIRATION = settings.MAX_EXPIRATION_HOURS
    CREATED_TOLERANCE = settings.CREATED_TOLERANCE_SECONDS
    
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        unique=True,
        blank=False,
        null=False,
        help_text="The user associated with this session.",
        verbose_name=_("User")
    )
    sessionId = models.CharField(
        verbose_name=_("Session Id"),
        max_length=32,
        unique=True,
        blank=False,
        null=False,
        editable=False,
        db_index=True,
        help_text="The unique identifier for this session\."
    )
    server = models.OneToOneField(
        Server,
        on_delete=models.CASCADE,
        unique=True,
        blank=False,
        null=False,
        help_text="The server where this session is active\.",
        verbose_name=_("Server")
    )
    expires = models.DateTimeField(
        verbose_name=_("Session expiry"),
        default=get_expiry_time_session,
        editable=False,
        help_text="The timestamp when this session will expire\."
    )
    created = models.DateTimeField(
        verbose_name=_("Created"),
        auto_now_add=True,
        editable=False,
        help_text="The timestamp when this session was created\."
    )
    
    def clean(self):
        """
        Performs additional validation on session data before saving\.
        Ensures required fields are set, verifies session expiration is within
        defined limits, checks creation time tolerance, validates parent server
        status, and confirms session ID format\.
        """
        super().clean()

        if not self.expires:
            raise ValidationError("Session has no expires time")
        try:
            if not self.server:
                raise ValidationError("Session has no server")
        except:
            raise ValidationError("Session has no server")
        
        if self.expires <= timezone.now() + timedelta(hours=self.MIN_EXPIRATION) - timedelta(seconds=self.CREATED_TOLERANCE):
            raise ValidationError(f"Expires time cannot be less than {self.MIN_EXPIRATION} hours from now.")
        if self.expires >= timezone.now() + timedelta(hours=self.MAX_EXPIRATION) + timedelta(seconds=self.CREATED_TOLERANCE):
            raise ValidationError(f"Expires time cannot be more than {self.MAX_EXPIRATION} hours from now.")
        
        if self.created  and abs(self.created - timezone.now()) > timedelta(seconds=self.CREATED_TOLERANCE):
            raise ValidationError(f"Created time seems unexpected. Please check system time.")

        if self.server:
            if self.server.trusty is False or self.server.available is False:
                raise ValidationError("Parent server must be trusted and available.")

        if not re.match(r"^[0-9a-f]{32}$", self.sessionId):
            raise ValidationError("Invalid session ID format.")
        
        if timezone.now() > self.expires:
            raise ValidationError("Session ID has expired.")
        
    def generate_valid_session_id(self):
        """
        Generate a valid 32-character hexadecimal session ID.
        """
        while True:
            session_id = uuid.uuid4().hex 
            if not Session.objects.filter(sessionId=session_id).exists():
                return session_id
        
    def save(self, *args, **kwargs):
        """
        Validates and saves the Session object.

        Generates a session ID if it's not set, performs full model validation,
        and prevents modification of the session ID after it's been set.
        """
        if self.pk is not None:
            original = Session.objects.get(pk=self.pk)
            if original.sessionId != self.sessionId:
                raise ValidationError("Cannot modify sessionId once it has been set.")
        
        if not self.sessionId:
            self.sessionId = self.generate_valid_session_id() 
            
        self.full_clean()
        super().save(*args, **kwargs)
        
    def __str__(self):
        """
        Returns a human-readable string representation of the Session object.

        This method is used whenever you need to convert a Session object into a string,
        such as when displaying it in the Django admin, debugging, or logging. It provides 
        a concise summary of the session's key information.

        **Returns:**
            str: A string representation of the session, formatted as:
                "session_id for server_name to time expiration_time"

        **Example:**
            If you have a session with ID "abc123def456", active on server "prod-server1"
            and expiring at 3 PM, calling `str(session_object)` would return:
            "abc123def456 for prod-server1 to time 2023-11-22 15:00:00"
        """
        return f"{self.sessionId} for {self.server.name} to time {self.expires}"
    
    class Meta:
        verbose_name = _("Session")
        verbose_name_plural = _("Session")
        ordering = ["-created"]

def get_expiry_time_token():
    """
    Calculates the expiration time for a temporary token.
    
    Returns:
        timezone.datetime: The expiration timestamp based on the current time and the configured expiration duration.
    """
    return timezone.now() + timedelta(minutes=settings.TEMPORARY_TOKEN_EXPIRATION_MINUTES)
    
class TemporaryToken(models.Model):
    """
    Model representing a temporary token assigned to a session with an expiration time.
    """
    TEMPORARY_TOKEN_EXPIRATION_MINUTES = settings.TEMPORARY_TOKEN_EXPIRATION_MINUTES
    CREATED_TOLERANCE = settings.CREATED_TOLERANCE_SECONDS
    
    token = models.CharField(
        verbose_name=_("Token"),
        max_length=128,
        unique=True,
        blank=False,
        editable=False,
        help_text="The unique token for calculate HMAC."
    )
    session = models.ForeignKey(
        Session,
        verbose_name=_("Session"),
        on_delete=models.CASCADE,
        editable=False,
        help_text=_("Session to which the temorary token is assigned."),
    )
    created_at = models.DateTimeField(
        verbose_name=_("Created"),
        auto_now_add=True,
        blank=False,
        editable=False,
        help_text="The timestamp when this token was created."
    )
    expires_at = models.DateTimeField(
        verbose_name=_("Temporary Token expiry"),
        default=get_expiry_time_token,
        editable=False,
        blank=False,
        help_text="The timestamp when this token will expire."
    )  
    
    path = models.CharField(
        verbose_name=_("path"),
        max_length=128,
        blank=False,
        editable=False,
        help_text="Path of the request."
    )

    def generate_temporary_token(self) -> str:
        """
        Generates a cryptographically secure temporary token.
        
        Returns:
            str: A 256-bit secure random token in URL-safe format.
        """
        return secrets.token_urlsafe(32) 
    
    def is_expired(self) -> bool:
        """
        Checks if the temporary token is expired.
        
        Returns:
            bool: True if the token has expired, False otherwise.
        """
        logger.info(f"Checking expiration: expires_at={self.expires_at}, now={timezone.now()}")
        return timezone.now() > self.expires_at
    
    def has_related_object(self,name:str) -> bool:
        """
        Checks if the token has a related object with the given attribute name.
        
        Args:
            name (str): The attribute name to check.
        
        Returns:
            bool: True if the related object exists, False otherwise.
        """
        return hasattr(self, name)
    
    def clean(self) -> None:
        """
        Validates the integrity and correctness of the temporary token instance.
        
        Raises:
            ValidationError: If any validation rule fails.
        """
        if not self.has_related_object("session"):
            raise ValidationError("no session to generate token")

        if self.is_expired():
            raise ValidationError("Token has expired.")

        if self.created_at  and abs(self.created_at - timezone.now()) > timedelta(seconds=self.CREATED_TOLERANCE):
            raise ValidationError(f"Created time seems unexpected. Please check system time.")
        
        logger.info(f"Token Validation: created_at={self.created_at}, expires_at={self.expires_at}")
        
        if self.created_at > self.expires_at:
            raise ValidationError(f"token has expired") 
        
        if self.session.expires < self.created_at:
            raise ValidationError(f"Session has expired") 
        
        super().clean()
    
    def save(self, *args, **kwargs) -> None:
        """
        Saves the temporary token instance, ensuring valid defaults are set.
        """
        if not self.token:
            self.token = self.generate_temporary_token()
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=self.TEMPORARY_TOKEN_EXPIRATION_MINUTES)  
        if not self.created_at:
            self.created_at = timezone.now()
            
        self.full_clean()
        
        logger.debug(f"Saving TemporaryToken: token=...., created_at={self.created_at}, expires_at={self.expires_at}")
        super().save(*args, **kwargs)
        
    def __str__(self) -> str:
        """
        Returns a human-readable representation of the TemporaryToken instance.
        
        Returns:
            str: A formatted string representing the token and its associated session.
        """
        return f"{self.token} for {self.session.sessionId}/{self.session.server.name}"
    
    class Meta:
        verbose_name = _("Temporary Token")
        verbose_name_plural = _("Temporary Token")
        ordering = ["-expires_at"]
    
