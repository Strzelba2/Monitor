from django.core.exceptions import ValidationError
from django.http import JsonResponse
from rest_framework import status
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from ..models import BlockedIP
from ..managers import LogManager
import logging

logger = logging.getLogger('django')

class RequestMiddleware(MiddlewareMixin):
    MAX_REQUESTS_PER_INTERVAL = 11
    BLOCK_DURATION = 60
    INTERVAL_DURATION_SECONDS = 8

    def process_request(self, request):
        
        logger.debug(f" process_request:")
        
        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        
        if ip_address:
            ip_address = ip_address.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR')
        
        LogManager.add_log_to_queue(
            path=request.path,
            method=request.method,
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT")
        )

        blocked_ip = BlockedIP.objects.filter(ip_address=ip_address).first()
        
        current_time = timezone.now()

        if blocked_ip and blocked_ip.blocked_until and blocked_ip.blocked_until > current_time:
            logger.debug(f" block ip:")
            return JsonResponse({'error': 'IP address blocked'}, status=status.HTTP_403_FORBIDDEN)

        request_count = LogManager.count_recent_requests(ip_address, seconds=self.INTERVAL_DURATION_SECONDS)
        logger.debug(f"request_count:{request_count}")
        
        if request_count > self.MAX_REQUESTS_PER_INTERVAL:
            logger.debug(f"self.MAX_REQUESTS_PER_INTERVAL:{self.MAX_REQUESTS_PER_INTERVAL}")
            try:
                BlockedIP.objects.create(
                    ip_address=ip_address,
                    blocked_until = current_time + timezone.timedelta(seconds=self.BLOCK_DURATION),
                    user_agent=request.META.get('HTTP_USER_AGENT'),
                    timestamp=current_time,
                    path=request.path
                    )
            except ValidationError as e:
                return JsonResponse({'error': str(e)}, status=status.HTTP_403_FORBIDDEN)
            except TypeError as e:
                return JsonResponse({'error': str(e)}, status=status.HTTP_403_FORBIDDEN)
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=status.HTTP_403_FORBIDDEN)
            
            return JsonResponse({'error': 'Too many requests'}, status=status.HTTP_403_FORBIDDEN)
        
        logger.debug(f"process request finished")
