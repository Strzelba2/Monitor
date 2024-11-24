from django.core.exceptions import ValidationError
from django.utils import timezone
import logging
import re

logger = logging.getLogger("django")

def validate_ip_address_with_port(value):

    ip_port_regex = r'^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$'
    logger.info(f"ip_port_regex : {re.match(ip_port_regex, value)}")
    
    if not re.match(ip_port_regex, value):
        raise ValidationError(f'{value} is not a valid IP address or IP:port format')
    
def validate_blocked_until(value):
    
    if value < timezone.now():
        logger.info(f"blocked_until : {value} < {timezone.now()} = {value < timezone.now()}")
        raise ValidationError("Blocked until cannot be earlier than the current time.")