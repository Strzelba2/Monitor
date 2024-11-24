from django.core.management.base import BaseCommand
from django.db import connections, OperationalError
from userauth.models import User
import time

import logging

logger = logging.getLogger('django')

class Command(BaseCommand):
    help = 'Initialize or update the allowed users file with existing usernames in the database.'
    
    def wait_for_db(self):
        """Waits until the database is ready before continuing."""
        logger.debug("wait_for_db")
        db_conn = connections['default']
        while True:
            try:
                db_conn.cursor()
                logger.debug("Database connection is available.")
                break
            except OperationalError:
                logger.warning("Database unavailable, waiting 1 second...")
                time.sleep(1)

    def handle(self, *args, **kwargs):
        
        self.wait_for_db()
        
        User.load_allowed_users()
        
        logger.debug("Allowed users set updated in-memory with active users.")

