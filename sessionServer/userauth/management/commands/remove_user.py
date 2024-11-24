from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from oauth2_provider.models import Application  


class Command(BaseCommand):
    help = "Remove a user and their related applications by username"

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='The username of the user to delete')

    def handle(self, *args, **options):
        username = options['username']
        try:
            # Fetch the user by username
            user = get_user_model().objects.get(username=username)

            # Delete related applications, if any
            Application.objects.filter(user=user).delete()

            # Delete the user
            user.delete()

            self.stdout.write(self.style.SUCCESS(
                f'Successfully deleted user {username} and associated applications.'
            ))
        except user.DoesNotExist:
            raise CommandError(f'User "{username}" does not exist.')