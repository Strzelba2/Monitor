from django.apps import AppConfig
import logging

logger = logging.getLogger('django')

class SessionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'session'
    

