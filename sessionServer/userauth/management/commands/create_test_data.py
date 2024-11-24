from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from oauth2_provider.models import Application
import os
import logging

logger = logging.getLogger('django')

class Command(BaseCommand):
    help = 'Create a test user and application dynamically'

    def handle(self, *args, **kwargs):
        username = os.getenv('TEST_USER_USERNAME', 'defaultUser')
        password = os.getenv('TEST_USER_PASSWORD', 'defau-lt.Passw!ord')
        lastname = os.getenv('TEST_USER_LASTNAME', 'defaultlastname')
        firstname = os.getenv('TEST_USER_FIRSTNAME', 'defaultfirstname')
        email = os.getenv('TEST_USER_EMAIL', 'defaultemail@example.com')
        client_id = os.getenv('TEST_CLIENT_ID', 'defaultClientId')
        client_secret = os.getenv('TEST_CLIENT_SECRET', 'defaultClientSecret')
        
        existing_user = get_user_model().objects.filter(username=username).first()
        
        if existing_user:
            logger.debug(f"User '{username}' already exists.")
            user, created = existing_user, False
        else:
            user, created = get_user_model().objects.get_or_create(
                                                                username=username,
                                                                email = email,
                                                                first_name= firstname,
                                                                last_name = lastname,
                                                                )
        if created:
            user.set_password(password)
            user.save()
            logger.debug(f"User '{username}' created successfully.")

        else:
            logger.debug(f"User '{username}' already exists.")
            
        application = Application.objects.filter(client_id=client_id).exists()
        
        if not application:

            application, created = Application.objects.get_or_create(
                user=user,
                client_type=Application.CLIENT_CONFIDENTIAL,
                authorization_grant_type=Application.GRANT_PASSWORD,
                client_id=client_id,
                client_secret=client_secret
            )
            if created:
                logger.debug("Application created successfully.")

            else:
                logger.debug("Application already exists.")
                
        
