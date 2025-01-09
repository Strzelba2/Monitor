from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from oauth2_provider.models import Application  
from requests.exceptions import SSLError
from django.conf import settings
import requests 

import logging

logger = logging.getLogger('django')

class Command(BaseCommand):
    help = 'Set client_secret for a given username'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Username for the client_secret retrieval')
        
    def set_ecrypted_secret(self, hashed_secret: str) -> str:

        url = f"{settings.SECRET_SERVER_URL}/set_secret"
        session = requests.Session()
        payload = {"hashed_secret": hashed_secret}

        try:
            logger.debug(f"Requesting PUT hashed secret")

            session.cert = (settings.SECRET_CERT_PATH, settings.SECRET_KEY_PATH)
            session.verify = settings.CA_CERT_PATH
            response = session.put(url, json=payload, timeout=10)
            
        except SSLError as e:
            logger.error(f"SSL error while requesting secret: {e}")
            raise e
        except TimeoutError as e:
            logger.error("Timeout error while requesting secret")
            raise e
        except requests.exceptions.RequestException as e:
            logger.error(f"An unexpected error occurred: {e}")
            raise e
            
            
        if response.status_code == 200:
            logger.debug("Secret server request successful")
        else:
            logger.error(f"Failed to set hashed secret: {response.status_code}, {response.text}")
            raise Exception(f"Failed to set hasjed secret: {response.status_code} - {response.text}")

    def handle(self, *args, **options):
        username = options['username']

        try:
            user = get_user_model().objects.get(username=username)
            application = Application.objects.get(user=user) 
            client_secret = application.client_secret
            logger.debug(f"loger client_secret: '{client_secret}' ")
            self.set_ecrypted_secret(client_secret)
            self.stdout.write(self.style.SUCCESS(f"client hashed secret seted succefully:{client_secret}"))
        except user.DoesNotExist:
            logger.debug('User not found')
            self.stdout.write(self.style.ERROR('User not found'))
        except Application.DoesNotExist:
            logger.debug('Application not found')
            self.stdout.write(self.style.ERROR('Application not found'))
        except Exception as e:
            logger.debug(f'{e}')
            self.stdout.write(self.style.ERROR(f'{e}'))