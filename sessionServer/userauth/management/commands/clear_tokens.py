from django.core.management.base import BaseCommand
from oauth2_provider.models import AccessToken, RefreshToken
from userauth.models import User
import logging

logger = logging.getLogger('django')

class Command(BaseCommand):
    help = "Clears all access and refresh tokens for a given user."

    def add_arguments(self, parser):
        parser.add_argument(
            'username', 
            type=str, 
            help='Username of the user whose tokens should be cleared.'
        )

    def handle(self, *args, **options):
        username = options.get('username')
        
        logger.debug("Test completed tokens begin to be cleared")

        if not username:
            self.stderr.write("Error: Username is required to clear tokens.")
            return

        try:
            user = User.objects.get(username=username)
            AccessToken.objects.filter(user=user).delete()
            RefreshToken.objects.filter(user=user).delete()
            logger.debug("Successfully cleared tokens for user: {username}")
            self.stdout.write(f"Successfully cleared tokens for user: {username}")
        except User.DoesNotExist:
            logger.warning("Error: User with username '{username}' does not exist.")
            self.stderr.write(f"Error: User with username '{username}' does not exist.")