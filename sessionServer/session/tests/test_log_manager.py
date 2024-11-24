from django.test import TestCase
from django.utils import timezone
from session.managers import LogManager
from session.models import RequestLog
import logging

logger = logging.getLogger('django')

class LogManagerTests(TestCase):
    def setUp(self):
        LogManager.clear_queue()

    def tearDown(self):
        LogManager.clear_queue()

    def test_add_log_to_queue(self):

        logger.debug(f"test_add_log_to_queue")
        path = "/test-path"
        method = "GET"
        ip_address = "127.0.0.1"
        user_agent = "TestAgent"

        LogManager.add_log_to_queue(path, method, ip_address, user_agent)
        logs = LogManager._redis_client.lrange(LogManager.REDIS_QUEUE_KEY, 0, -1)

        self.assertEqual(len(logs), 1)
        log_data = eval(logs[0])
        self.assertEqual(log_data["path"], path)
        self.assertEqual(log_data["method"], method)
        self.assertEqual(log_data["ip_address"], ip_address)
        self.assertEqual(log_data["user_agent"], user_agent)

    def test_count_recent_requests(self):

        logger.debug(f"test_count_recent_requests")
        ip_address = "127.0.0.1"
        other_ip = "192.168.1.1"
        timestamp_now = timezone.now()

        LogManager._redis_client.rpush(
            LogManager.REDIS_QUEUE_KEY,
            str({
                "path": "/test-path",
                "method": "GET",
                "ip_address": ip_address,
                "user_agent": "TestAgent",
                "timestamp": timestamp_now.isoformat()
            }),
        )
        LogManager._redis_client.rpush(
            LogManager.REDIS_QUEUE_KEY,
            str({
                "path": "/test-path-2",
                "method": "POST",
                "ip_address": other_ip,
                "user_agent": "TestAgent2",
                "timestamp": timestamp_now.isoformat()
            }),
        )

        recent_count = LogManager.count_recent_requests(ip_address, seconds=60)
        self.assertEqual(recent_count, 1)

    def test_batch_insert_logs(self):

        logger.debug(f"test_batch_insert_logs")
        ip_address = "127.0.0.1"

        LogManager.add_log_to_queue("/test-path", "GET", "127.0.0.1", "TestAgent")

        LogManager.batch_insert_logs()

        self.assertEqual(RequestLog.objects.count(), 1)
        log = RequestLog.objects.first()
        self.assertEqual(log.path, "/test-path")
        self.assertEqual(log.method, "GET")
        self.assertEqual(log.ip_address, ip_address)
        self.assertEqual(log.user_agent, "TestAgent")

        logs = LogManager._redis_client.lrange(LogManager.REDIS_QUEUE_KEY, 0, -1)
        self.assertEqual(len(logs), 0)

    def test_clear_queue(self):

        logger.debug(f"test_clear_queue")

        LogManager.add_log_to_queue("/test-path", "GET", "127.0.0.1", "TestAgent")
        LogManager.add_log_to_queue("/test-path-2", "POST", "192.168.1.1", "TestAgent2")

        logs = LogManager._redis_client.lrange(LogManager.REDIS_QUEUE_KEY, 0, -1)
        self.assertEqual(len(logs), 2)

        LogManager.clear_queue()

        logs = LogManager._redis_client.lrange(LogManager.REDIS_QUEUE_KEY, 0, -1)
        self.assertEqual(len(logs), 0)
        
    def test_get_logs_from_queue(self):
        logger.debug(f"test_get_logs_from_queue")

        LogManager.add_log_to_queue("/test-path", "GET", "127.0.0.1", "TestAgent")
        LogManager.add_log_to_queue("/test-path-2", "POST", "192.168.1.1", "TestAgent2")

        logs = LogManager.get_logs_from_queue()

        self.assertEqual(len(logs), 2)

        remaining_logs = LogManager._redis_client.lrange(LogManager.REDIS_QUEUE_KEY, 0, -1)
        self.assertEqual(len(remaining_logs), 2)