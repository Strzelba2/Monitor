import redis
from .models import RequestLog
from django.utils import timezone
from django.db import transaction
import logging
import json


logger = logging.getLogger('django')

class LogManager:
    REDIS_QUEUE_KEY = "log_queue"
    _redis_client = redis.StrictRedis(host='redis', port=6379, db=0, decode_responses=True)

    @classmethod
    def add_log_to_queue(cls, path, method, ip_address, user_agent):

        logger.debug(f" add_log_to_queue")
        log_entry = {
            "path": path,
            "method": method,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "timestamp": timezone.now().isoformat(), 
        }
        serialized_log = json.dumps(log_entry)
        cls._redis_client.rpush(cls.REDIS_QUEUE_KEY, serialized_log)

    @classmethod
    def count_recent_requests(cls, ip_address, seconds=60):

        logger.debug(f"count_recent_requests")
        start_time = timezone.now() - timezone.timedelta(seconds=seconds)
        recent_count = 0

        logs = cls._redis_client.lrange(cls.REDIS_QUEUE_KEY, 0, -1)
        
        for log in logs:
            log = log.replace("'", '"')
            log_data = json.loads(log)
            log_time = timezone.datetime.fromisoformat(log_data["timestamp"])
            
            if log_data["ip_address"] == ip_address and log_time >= start_time:
                recent_count += 1
        
        return recent_count
    
    @classmethod
    def get_logs_from_queue(cls):

        logger.debug(f"get_logs_from_queue")
        try:
            logs = cls._redis_client.lrange(cls.REDIS_QUEUE_KEY, 0, -1)
            logger.debug(f"{logs}")
            parsed_logs = [json.loads(log) for log in logs]

            logger.debug(f"{parsed_logs}")
            return parsed_logs
        except redis.RedisError as e:
            logger.error(f"Error fetching logs from Redis: {e}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding logs from Redis: {e}")
            return []

    @classmethod
    def batch_insert_logs(cls):
        logger.debug(f"batch_insert_logs")
        logs = cls.get_logs_from_queue()
        if not logs:
            return 

        logger.debug(f"{logs}")

        logs_to_insert = [
            RequestLog(
                path=log["path"],
                method=log["method"],
                ip_address=log["ip_address"],
                user_agent=log["user_agent"],
                timestamp=log["timestamp"],
            )
            for log in logs
        ]
        
        logger.debug(f"{logs}")

        try:
            with transaction.atomic():
                RequestLog.objects.bulk_create(logs_to_insert)

            cls.clear_queue()
        except Exception as e:
            logger.error(f"Batch insert failed: {e}")

    @classmethod
    def clear_queue(cls):

        logger.debug(f"clear_queue")
        
        cls._redis_client.delete(cls.REDIS_QUEUE_KEY)