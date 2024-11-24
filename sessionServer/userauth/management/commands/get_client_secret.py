from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from oauth2_provider.models import Application  

import logging

logger = logging.getLogger('django')

class Command(BaseCommand):
    help = 'Retrieves client_secret for a given username'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Username for the client_secret retrieval')

    def handle(self, *args, **options):
        username = options['username']

        try:
            user = get_user_model().objects.get(username=username)
            application = Application.objects.get(user=user) 
            client_secret = application.client_secret
            logger.debug(f"loger client_secret: '{client_secret}' ")
            self.stdout.write(self.style.SUCCESS(f"client_secret:{client_secret}"))
        except user.DoesNotExist:
            logger.debug('User not found')
            self.stdout.write(self.style.ERROR('User not found'))
        except Application.DoesNotExist:
            logger.debug('Application not found')
            self.stdout.write(self.style.ERROR('Application not found'))