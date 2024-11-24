from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _
import logging

logger = logging.getLogger("django")

class UserauthConfig(AppConfig):
    """
    Configuration class for the 'userauth' application.

    This class provides metadata and configuration options for the app,
    such as the application name, verbose name, and additional setup
    actions during app initialization.
    """
    logger.info("UserauthConfig")
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'userauth'
    verbose_name = _("Users")
    
    def ready(self) -> None:
        import userauth.signals
        
        logger.info("userauth signals module imported in ready()")
        
        
