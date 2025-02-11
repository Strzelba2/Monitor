import redis
from .models import RequestLog
from django.utils import timezone
from django.db import transaction
import logging
import json

logger = logging.getLogger('django')

class LogManager:
    """
    A manager class for handling log entries using Redis as a temporary storage queue.
    """
    
    REDIS_QUEUE_KEY = "log_queue"
    _redis_client = redis.StrictRedis(host='redis', port=6379, db=0, decode_responses=True)

    @classmethod
    def add_log_to_queue(cls, path: str, method: str, ip_address: str, user_agent: str) -> None:
        """
        Adds a log entry to the Redis queue.

        Args:
            path (str): The request path.
            method (str): The HTTP method used (GET, POST, etc.).
            ip_address (str): The IP address of the requester.
            user_agent (str): The User-Agent string of the requester.
        """
        log_entry = {
            "path": path,
            "method": method,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "timestamp": timezone.now().isoformat(), 
        }
        serialized_log = json.dumps(log_entry)
        cls._redis_client.rpush(cls.REDIS_QUEUE_KEY, serialized_log)
        
        logger.debug(f"Added log to queue: {log_entry}")

    @classmethod
    def count_recent_requests(cls, ip_address: str, seconds: int = 60) -> int:
        """
        Counts the number of requests from a specific IP address in the last `seconds` seconds.

        Args:
            ip_address (str): The IP address to filter by.
            seconds (int, optional): Time window in seconds. Defaults to 60.

        Returns:
            int: The count of recent requests from the given IP.
        """
        start_time = timezone.now() - timezone.timedelta(seconds=seconds)
        recent_count = 0

        logs = cls._redis_client.lrange(cls.REDIS_QUEUE_KEY, 0, -1)
        
        for log in logs:
            log = log.replace("'", '"')
            log_data = json.loads(log)
            log_time = timezone.datetime.fromisoformat(log_data["timestamp"])
            
            if log_data["ip_address"] == ip_address and log_time >= start_time:
                recent_count += 1
        
        logger.debug(f"Recent requests from {ip_address} in the last {seconds} seconds: {recent_count}")
        return recent_count
    
    @classmethod
    def get_logs_from_queue(cls) -> list[dict]:
        """
        Retrieves all log entries from the Redis queue.

        Returns:
            list[dict]: A list of log dictionaries retrieved from Redis.
        """
        try:
            logs = cls._redis_client.lrange(cls.REDIS_QUEUE_KEY, 0, -1)
            logger.debug(f"{logs}")
            parsed_logs = [json.loads(log) for log in logs]

            logger.debug(f"Retrieved logs from queue: {parsed_logs}")
            return parsed_logs
        except redis.RedisError as e:
            logger.error(f"Error fetching logs from Redis: {e}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding logs from Redis: {e}")
            return []

    @classmethod
    def batch_insert_logs(cls) -> None:
        """
        Retrieves logs from the queue and inserts them into the database in a batch operation.
        """
        logs = cls.get_logs_from_queue()
        if not logs:
            logger.debug("No logs to insert. Queue is empty.")
            return 

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
        
        logger.debug(f"Batch inserting logs: {logs_to_insert}")

        try:
            with transaction.atomic():
                RequestLog.objects.bulk_create(logs_to_insert)
            cls.clear_queue()
            logger.info(f"Successfully inserted {len(logs_to_insert)} logs into the database.")
        except Exception as e:
            logger.error(f"Batch insert failed: {e}")

    @classmethod
    def clear_queue(cls) -> None:
        """
        Clears the Redis log queue.
        """
        
        cls._redis_client.delete(cls.REDIS_QUEUE_KEY)
        logger.debug("Cleared Redis log queue.")