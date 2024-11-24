from celery import shared_task
from .managers import LogManager
from django.utils import timezone
from .models import RequestLog
import logging

logger = logging.getLogger('django')

@shared_task(name="batch_insert_logs_task")
def batch_insert_logs_task():
    """
    Celery task for batch inserting logs into the database.
    """
    logger.info("Starting batch log insertion...")
    try:
        LogManager.batch_insert_logs()
        logger.info("Batch log insertion completed successfully.")
    except Exception as e:
        logger.error(f"Error during batch log insertion: {str(e)}")
  
@shared_task(name="delete_old_request_log")      
def delete_old_request_logs():
    cutoff_date = timezone.now() - timezone.timedelta(days=2)
    RequestLog.objects.filter(timestamp__lt=cutoff_date).delete()
  
