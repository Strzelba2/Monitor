from django.test import TestCase
from django.conf import settings
from django.utils import timezone
from session.models import BlockedIP, RequestLog, Server, Session, TemporaryToken
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from datetime import timedelta
import uuid
import logging

logger = logging.getLogger("test_logger")

BLOCKED_UNTIL_DEFAULT_SECONDS = 1200
IP_ADDRESS = "192.168.0.1"

class BlockedIPModelTest(TestCase):
    
    def test_blocked_ip_creation(self): 
        """Test creation of BlockedIP model instance"""
        
        logger.info("Starting test: test_blocked_ip_creation")
        
        expected_blocked_until = timezone.now() + timezone.timedelta(seconds=BLOCKED_UNTIL_DEFAULT_SECONDS)
        expected_timestamp = timezone.now()
        
        logger.info(f"Expected Timestamp: {expected_timestamp}, Blocked Until: {expected_blocked_until}")
        
        blocked_ip = BlockedIP.objects.create(
            ip_address=IP_ADDRESS,
            path='/blocked',
            user_agent='TestAgent',
            blocked_until=expected_blocked_until,
            timestamp=expected_timestamp 
        )
        self.assertEqual(blocked_ip.ip_address, IP_ADDRESS,"ip_address should be 192.168.0.1")
        self.assertEqual(str(blocked_ip), IP_ADDRESS,"str(blocked_ip) should be 192.168.0.1")
        self.assertAlmostEqual(blocked_ip.blocked_until, expected_blocked_until, delta=timezone.timedelta(seconds=1))
        self.assertAlmostEqual(blocked_ip.timestamp, expected_timestamp, delta=timezone.timedelta(seconds=1))
        self.assertEqual(blocked_ip.path, '/blocked', "path should be /blocked")
        self.assertEqual(blocked_ip.user_agent, 'TestAgent', "user_agent should be TestAgent")
        
        logger.info("Test passed: test_blocked_ip_creation")
        
    def test_defaults_are_set(self):
        """Test that the default values for blocked_until, path, user_agent, and timestamp are set correctly."""
        
        logger.info("Starting test: test_defaults_are_set")
        
        expected_blocked_until = timezone.now() + timezone.timedelta(seconds=BLOCKED_UNTIL_DEFAULT_SECONDS)
        
        blocked_ip = BlockedIP.objects.create(ip_address=IP_ADDRESS)
        
 
        self.assertEqual(blocked_ip.path, "/default", "path should be /default")
        self.assertEqual(blocked_ip.user_agent, "","Default user agent should be an empty string.")
        self.assertAlmostEqual(blocked_ip.blocked_until, expected_blocked_until, delta=timezone.timedelta(seconds=1))
        
        logger.info("Test passed: test_defaults_are_set")
        
    def test_timestamp_is_aware(self):
        """Test that the timestamp is timezone-aware."""
        
        logger.info("Starting test: test_timestamp_is_aware")
        
        blocked_ip = BlockedIP.objects.create(ip_address=IP_ADDRESS)
        
        self.assertTrue(timezone.is_aware(blocked_ip.timestamp),"Timestamp should be timezone-aware.")
        
        logger.info("Test passed: test_timestamp_is_aware")
        
    def test_blocked_until_is_aware(self):
        """Test that blocked_until is timezone-aware."""
        
        logger.info("Starting test: test_blocked_until_is_aware")
        
        blocked_ip = BlockedIP.objects.create(ip_address=IP_ADDRESS)
        
        self.assertTrue(timezone.is_aware(blocked_ip.blocked_until), "blocked_until should be timezone-aware.")
        
        logger.info("Test passed: test_blocked_until_is_aware")
        
    def test_max_length_constraints(self):
        """Test that the ip_address, path, and user_agent fields respect max_length."""
        
        logger.info("Starting test: test_max_length_constraints")

        blocked_ip = BlockedIP.objects.create(
            ip_address=IP_ADDRESS, 
            path="/some/really/long/path/" * 30, 
            user_agent="Mozilla/5.0" * 30 
        )

        self.assertLessEqual(len(blocked_ip.path), 255, "Path length exceeds 255 characters.")
        self.assertLessEqual(len(blocked_ip.user_agent), 255, "User agent length exceeds 255 characters.")
        
        logger.info("Test passed: test_max_length_constraints")
        
    def test_valid_ip_without_port(self):
        """Test valid IP without port"""
        
        logger.info("Starting test: test_valid_ip_without_port")
        
        try:
            BlockedIP.objects.create(ip_address=IP_ADDRESS)
        except ValidationError:
            self.fail("IP address without port raised ValidationError unexpectedly!")
            
        logger.info("Test passed: test_valid_ip_without_port")

    def test_valid_ip_with_port(self):
        """Test valid IP with port"""
        logger.info("Starting test: test_valid_ip_with_port")
        try:
            BlockedIP.objects.create(ip_address=f"{IP_ADDRESS}:8080") 
        except ValidationError:
            self.fail("IP address with port raised ValidationError unexpectedly!")
            
        logger.info("Test passed: test_valid_ip_with_port")

    def test_invalid_ip_format(self):
        """Test invalid IP format"""
        logger.info("Starting test: test_invalid_ip_format")

        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address="999.999.999.999.999")
            
        logger.info("Test passed: test_invalid_ip_format")
        
    def test_invalid_ip_format_no_numbers(self):
        """Test invalid IP format"""
        logger.info("Starting test: test_invalid_ip_format_no_numbers")

        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address="sde.dsa.ffe.jhy")
            
        logger.info("Test passed: test_invalid_ip_format_no_numbers")

    def test_invalid_ip_with_invalid_port(self):
        """Test invalid IP with invalid port"""
        
        logger.info("Starting test: test_invalid_ip_with_invalid_port")

        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address=f"{IP_ADDRESS}:avf9d78")
            
        logger.info("Test passed: test_invalid_ip_with_invalid_port")

    def test_invalid_non_numeric_ip(self):
        """Test non-numeric IP address"""
        
        logger.info("Starting test: test_invalid_non_numeric_ip")
        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address="invalid_ip")
            
        logger.info("Test passed: test_invalid_non_numeric_ip")
            
    def test_create_without_ip(self):
        """Test creating BlockedIP without an IP address"""
        
        logger.info("Starting test: test_create_without_ip")
        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address=None)
            
        logger.info("Test passed: test_create_without_ip")
            
    def test_update_blocked_until(self):
        """Test updating blocked_until field"""
        logger.info("Starting test: test_update_blocked_until")
        
        blocked_ip = BlockedIP.objects.create(ip_address=IP_ADDRESS)
        new_time = timezone.now() + timezone.timedelta(hours=1)
        blocked_ip.blocked_until = new_time
        blocked_ip.save()

        self.assertEqual(blocked_ip.blocked_until, new_time, "blocked_until should be equal new_time")
        
        logger.info("Test passed: test_update_blocked_until")
        
    def test_delete_blocked_ip(self):
        """Test deleting a BlockedIP instance"""
        
        logger.info("Starting test: test_delete_blocked_ip")
        
        blocked_ip = BlockedIP.objects.create(ip_address=IP_ADDRESS)
        blocked_ip.delete()
        self.assertFalse(BlockedIP.objects.filter(ip_address=IP_ADDRESS).exists(),"should be False")
        
        logger.info("Test passed: test_delete_blocked_ip")
        
    def test_conflict_on_same_ip(self):
        """Test that creating two BlockedIP instances with the same IP raises a conflict."""
        
        logger.info("Starting test: test_conflict_on_same_ip")
        
        blocked_ip_1 = BlockedIP.objects.create(ip_address=IP_ADDRESS)

        with self.assertRaises(ValidationError):
            blocked_ip_2 = BlockedIP.objects.create(ip_address=IP_ADDRESS)
            
        logger.info("Test passed: test_conflict_on_same_ip")
        
    def test_update_conflict_on_same_ip(self):
        """The test updates the ip address to an existing one. It should throw up a conflict"""
        
        logger.info("Starting test: test_update_conflict_on_same_ip")
        
        BlockedIP.objects.create(ip_address=IP_ADDRESS)

        with self.assertRaises(ValidationError):
            blocked_ip = BlockedIP.objects.create(ip_address="192.168.0.12")
            blocked_ip.ip_address = IP_ADDRESS
            blocked_ip.save()
            
        logger.info("Test passed: test_update_conflict_on_same_ip")
        
    def test_timestamp_wrong_format(self):
        """test checks invalid timestamp format"""
        
        logger.info("Starting test: test_timestamp_wrong_format")
        
        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address=IP_ADDRESS,
                                                  timestamp = "wrong")
        logger.info("Test passed: test_timestamp_wrong_format")
        
    def test_blocked_until_wrong_format(self):
        """test checks invalid blocked_until format"""
        
        logger.info("Starting test: test_blocked_until_wrong_format")
        
        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address=IP_ADDRESS,
                                                  blocked_until = "wrong")
            
        logger.info("Test passed: test_blocked_until_wrong_format")
        
    def test_blocked_until_blank(self):
        """test checks if it is possible to assign an empty item to blocked_until"""
        
        logger.info("Starting test: test_blocked_until_blank")
        
        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address=IP_ADDRESS,
                                                  blocked_until = "")
            
        logger.info("Test passed: test_blocked_until_blank")
        
    def test_timestamp_blank(self):
        """test checks if it is possible to assign an empty item to timestamp"""
        
        logger.info("Starting test: test_blocked_until_blank")
        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address=IP_ADDRESS,
                                                  timestamp = "")
        logger.info("Test passed: test_blocked_until_blank")
        
    def test_path_blank(self):
        """test checks if it is possible to assign an empty item to path"""
        
        logger.info("Starting test: test_path_blank")
        
        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address=IP_ADDRESS,
                                                  path = "")
            
        logger.info("Test passed: test_path_blank")
        
            
    def test_blocked_until_cannot_be_in_the_past(self):
        """Test that blocked_until cannot be set in the past."""
        
        logger.info("Starting test: test_blocked_until_cannot_be_in_the_past")
        
        with self.assertRaises(ValidationError):
            BlockedIP.objects.create(ip_address=IP_ADDRESS,
                blocked_until=timezone.now() - timezone.timedelta(seconds=60)) 
            
        logger.info("Test passed: test_blocked_until_cannot_be_in_the_past")
        
    def test_ordering(self):
        """
        Test that BlockedIP objects are ordered by the blocked_until field in ascending order.

        The test creates two BlockedIP instances with different blocked_until times and
        verifies that the instance with the earlier blocked_until value appears first
        when retrieving all BlockedIP objects from the database.
        """
        
        logger.info("Starting test: test_ordering")
        
        blocked_ip1 = BlockedIP.objects.create(ip_address=IP_ADDRESS, blocked_until=timezone.now()+ timezone.timedelta(hours=1))
        blocked_ip2 = BlockedIP.objects.create(ip_address="192.168.0.2", blocked_until=timezone.now() + timezone.timedelta(hours=2))
        blocked_ips = BlockedIP.objects.all()
        
        logger.info(f"List: {blocked_ips}")

        self.assertEqual(blocked_ips[0], blocked_ip2)
        self.assertEqual(blocked_ips[1], blocked_ip1)
        
        logger.info("Test passed test_ordering")
        
    def test_bulk_create(self):
        """
        Test the bulk_create method for efficiently inserting multiple BlockedIP instances.

        This test ensures that multiple BlockedIP instances can be created in a single query
        using the bulk_create method, and verifies that the total number of records in the 
        BlockedIP table reflects the correct count after creation.
        """
        
        logger.info("Starting test: test_bulk_create")
        
        BlockedIP.objects.bulk_create([
            BlockedIP(ip_address=IP_ADDRESS),
            BlockedIP(ip_address="192.168.0.2")
        ])
        
        self.assertEqual(BlockedIP.objects.count(), 2, "should be two objects" )
        
        logger.info("Test passed: test_bulk_create")
        
    def test_string_representation(self):
        """
        Test the __str__ method of the BlockedIP model.

        This test ensures that the string representation of a BlockedIP instance 
        returns the expected IP address, which should match the ip_address field 
        of the instance.
        """
        
        logger.info("Starting test: test_string_representation")
        
        blocked_ip = BlockedIP.objects.create(ip_address=IP_ADDRESS)
        self.assertEqual(str(blocked_ip), IP_ADDRESS , "address ip should be 192.168.0.1")
        
        logger.info("Test passed: test_string_representation")
        
    def test_save_invalid_ip_address(self):
        """Test that save() raises ValidationError for an invalid IP address"""
        
        logger.info("Starting test: test_save_invalid_ip_address")
        
        blocked_ip = BlockedIP(ip_address="999.999.999.999.999")
        with self.assertRaises(ValidationError):
            blocked_ip.save() 
            
        logger.info("Test passed: test_save_invalid_ip_address")
            
    def test_save_method_preserves_other_fields(self):
        """Test that the save method does not affect other fields"""
        
        logger.info("Starting test: test_save_method_preserves_other_fields")
        
        expected_blocked_until = timezone.now() + timezone.timedelta(seconds=BLOCKED_UNTIL_DEFAULT_SECONDS)
        blocked_ip = BlockedIP(ip_address=IP_ADDRESS, path="/test", user_agent="TestAgent")
        blocked_ip.save()

        self.assertEqual(blocked_ip.ip_address, IP_ADDRESS, "address ip should be 192.168.0.1")
        self.assertEqual(blocked_ip.path, "/test", "path should be /test")
        self.assertEqual(blocked_ip.user_agent, "TestAgent", "user_agent should be TestAgent")
        
        self.assertAlmostEqual(blocked_ip.blocked_until, expected_blocked_until, delta=timezone.timedelta(seconds=1))
        
        logger.info("Test passed: test_save_method_preserves_other_fields")
        
    def test_invalid_data_type_raises_type_error(self):
        """Test that a ValidationError is raised when a non-string type is assigned to a field."""
        blocked_ip = BlockedIP()
        
        logger.info("Starting test: test_invalid_data_type_raises_type_error")
        
        with self.assertRaises(ValidationError):
            blocked_ip.ip_address = 123 
            blocked_ip.save()

        with self.assertRaises(ValidationError):
            blocked_ip.path = 123 
            blocked_ip.save()
            
        with self.assertRaises(ValidationError):
            blocked_ip.user_agent = 123 
            blocked_ip.save()
            
        logger.info("Test passed: test_invalid_data_type_raises_type_error")
        
class RequestLogModelTest(TestCase):
    
    def test_request_log_creation(self):
        """
        Test the creation of a RequestLog instance.
        Ensure all fields are set correctly.
        """
        logger.info("Starting test: request_log_creation")

        log = RequestLog.objects.create(
            path='/test-path',
            method='GET',
            ip_address=IP_ADDRESS,
            user_agent='Mozilla/5.0'
        )
        self.assertEqual(log.path, '/test-path')
        self.assertEqual(log.method, 'GET')
        self.assertEqual(log.ip_address, IP_ADDRESS)
        self.assertEqual(log.user_agent, 'Mozilla/5.0')
        self.assertTrue(timezone.now() - log.timestamp < timezone.timedelta(seconds=5))
    
        logger.info("Test passed: request_log_creation")    
        
    def test_request_log_default_values(self):
        """
        Test the default values (nullability) for fields that allow null/blank.
        Ensure that empty fields do not raise errors and are correctly set to None.
        """
        
        logger.info("Starting test: test_request_log_default_values")
        
        log = RequestLog.objects.create()
        self.assertIsNone(log.path)
        self.assertIsNone(log.method)
        self.assertIsNone(log.ip_address)
        self.assertIsNone(log.user_agent)
        self.assertTrue(timezone.now() - log.timestamp < timezone.timedelta(seconds=5))
        
        logger.info("Test passed: test_request_log_default_values")
        
    def test_string_representation(self):
        """
        Test the string representation (__str__) of the RequestLog model.
        Ensure it returns the correct format: "METHOD PATH from IP at TIMESTAMP".
        """
        
        logger.info("Starting test: test_string_representation")
        
        log = RequestLog.objects.create(
            path='/test-path',
            method='POST',
            ip_address=IP_ADDRESS,
            user_agent='TestAgent'
        )
        expected_str = f"POST /test-path from {IP_ADDRESS} at {log.timestamp}"
        self.assertEqual(str(log), expected_str)
        
        logger.info("Test Passed: test_string_representation")
        
    def test_max_length_constraints(self):
        """
        Test that the fields with max_length constraints respect their limits.
        Ensure no value exceeds the max length.
        """
        
        logger.info("Starting test: test_max_length_constraints")
        
        log = RequestLog.objects.create(
            path='a' * 260,
            method='PUT'* 10,
            ip_address=IP_ADDRESS*5,
            user_agent='b' * 260
        )
        self.assertEqual(len(log.path), 255)
        self.assertEqual(len(log.method), 10)
        self.assertEqual(len(log.ip_address), 45) 
        self.assertEqual(len(log.user_agent), 255)
        
        logger.info("Test passed: test_max_length_constraints")
        
            
    def test_save_preserves_other_fields(self):
        """
        Test that saving the model preserves values in other fields.
        Ensure that updating one field does not affect others.
        """
        log = RequestLog.objects.create(
            path='/initial-path',
            method='GET',
            ip_address=IP_ADDRESS,
            user_agent='InitialAgent'
        )
        log.path = '/updated-path'
        log.save()
        
        updated_log = RequestLog.objects.get(pk=log.pk)
        self.assertEqual(updated_log.path, '/updated-path')
        self.assertEqual(updated_log.method, 'GET')
        self.assertEqual(updated_log.ip_address, IP_ADDRESS)
        self.assertEqual(updated_log.user_agent, 'InitialAgent')
        
    def test_timestamp_creation(self):
        """
        Test the creation of a RequestLog instance.
        Ensure all fields are set correctly.
        """
        logger.info("Starting test: test_timestamp_creation")

        log = RequestLog.objects.create(
            timestamp=timezone.now()
        )
        self.assertTrue(timezone.now() - log.timestamp < timezone.timedelta(seconds=5))
    
        logger.info("Test passed: test_timestamp_creation")   
        
    def test_invalid_data_type_raises_type_error(self):
        """Test that a TypeError is raised when a non-string type is assigned to a field."""
        
        logger.info("Starting test: test_invalid_data_type_raises_type_error")
        
        request_log = RequestLog()

        with self.assertRaises(ValidationError):
            request_log.path = 123 
            request_log.save()
            
        with self.assertRaises(ValidationError):
            request_log.method = 123 
            request_log.save()
            
        with self.assertRaises(ValidationError):
            request_log.ip_address = 123 
            request_log.save()
            
        with self.assertRaises(ValidationError):
            request_log.user_agent = 123  
            request_log.save()
            
        logger.info("Test passed: test_invalid_data_type_raises_type_error")
            
    def test_invalid_timestamp_raises_error(self):
        """Test that an error is raised when an invalid timestamp is set."""
        
        logger.info("Starting test: test_invalid_timestamp_raises_error")    
    
        request_log = RequestLog(
            path='/example',
            method='GET',
            ip_address=IP_ADDRESS,
            user_agent='Mozilla/5.0',
            timestamp='invalid_date'  
        )

        with self.assertRaises(ValidationError):
            request_log.save()
        
        logger.info("Test passed: test_invalid_timestamp_raises_error")  
        
    def test_delete_log(self):
        """Test deleting a RequestLog instance"""
        
        logger.info("Starting test: test_delete_log")
        
        log = RequestLog.objects.create(
            path='/initial-path',
            method='GET',
            ip_address=IP_ADDRESS,
            user_agent='InitialAgent'
        )

        log.delete()
        self.assertFalse(RequestLog.objects.filter(ip_address=IP_ADDRESS).exists(),"should be False")
        
        logger.info("Test passed: test_delete_log") 
        
    
class ServerModelTest(TestCase):
    """
    Unit tests for the Server model, ensuring correct behavior for various model features
    such as validations, data integrity, and edge cases.
    """
    
    def setUp(self):
        """
        Set up a user and valid server data to be used in the tests.
        This method creates a user and defines a dictionary for valid server data.
        """

        self.user = get_user_model().objects.create_user(
            first_name='testuser',
            last_name='Czwarty',
            username='testuser',
            email='testuser@example.com',
            password='testD.pass123'
            
        )
    
        self.valid_data = {
            'name': 'Valid Server',
            'ip_address': IP_ADDRESS,
            'port':8080,
            'location': 'Data Center',
            'user': self.user,  
            'trusty': True,
            'available': True
        }
    
    def test_server_creation(self):
        """
        Test the creation of a Server model instance.
        Ensure that the server is created with valid data, and that the 
        fields like `name`, `ip_address`, and `user` are correctly set.
        """
        logger.info("Starting test: server_creation")
        server = Server.objects.create(
            name='TestServer',
            ip_address=IP_ADDRESS,
            port=8080,
            location='Datacenter',
            user=self.user,
            trusty=True,
            available=True
        )
        self.assertEqual(server.name, 'TestServer')
        self.assertEqual(server.ip_address, IP_ADDRESS)
        self.assertTrue(server.trusty)
        self.assertEqual(str(server), 'TestServer')
        self.assertEqual(server.user, self.user)
        
        logger.info("Test passed: server_creation") 
        
    def test_server_creation_without_user(self):
        """
        Test the creation of a Server model without specifying a user.
        Ensure that the server is created successfully with `user` set to None.
        """
        logger.info("Starting test: test_server_creation_without_user")
        server = Server.objects.create(
            name='Server Without User',
            ip_address=IP_ADDRESS,
            port=8080,
            location='Datacenter',
            user=None,
            trusty=True,
            available=True
        )
        self.assertIsNone(server.user)
        
        logger.info("Test passed: test_server_creation_without_user")
        
    def test_invalid_name_type_raises_error(self):
        """
        Ensure that saving a server with an invalid `name` data type raises an error.
        In this case, `name` should be a string, so using an integer will raise a TypeError.
        """
        logger.info("Starting test: test_invalid_name_type_raises_error")

        with self.assertRaises(ValidationError):
            Server.objects.create(
                name=123,
                ip_address=IP_ADDRESS,
                port=8080,
                location='Datacenter',
                user=self.user,
                trusty=True,
                available=True
            )
            
        logger.info("Test passed: test_invalid_name_type_raises_error")
            
    def test_name_max_length(self):
        """
        Test that the `name` field is truncated to 100 characters when it's too long.
        """
        logger.info("Starting test: test_name_max_length")
        
        server = Server(**self.valid_data)
        server.name = 'A' * 105  
        server.save()
        self.assertEqual(len(server.name), 100)
        
        logger.info("Test passed: test_name_max_length")
            
    def test_empty_name_raises_error(self):
        """
        Ensure that saving a server with an empty or None `name` raises a ValidationError.
        """
        logger.info("Starting test: test_empty_name_raises_error")
          
        with self.assertRaises(ValidationError):
            Server.objects.create(
                name='',
                ip_address=IP_ADDRESS,
                port=8080,
                location='Datacenter',
                user=self.user,
                trusty=True,
                available=True
            )
        
        with self.assertRaises(ValidationError):
            Server.objects.create(
                name=None,
                ip_address=IP_ADDRESS,
                port=8080,
                location='Datacenter',
                user=self.user,
                trusty=True,
                available=True
            )
            
        logger.info("Test passed: test_empty_name_raises_error")
            
    def test_ip_address_is_required(self):
        """
        Ensure that a server cannot be saved without an IP address.
        An IP address is a required field.
        """
        logger.info("Starting test: test_ip_address_is_required")
        
        server = Server(**self.valid_data)
        server.ip_address = None
        with self.assertRaises(ValidationError):
            server.save()
            
        logger.info("Test passed: test_ip_address_is_required")
            
    def test_ip_address_incorrect_data_type(self):
        """
        Ensure that a server cannot be saved with an incorrect data type for the IP address.
        """
        logger.info("Starting test: test_ip_address_incorrect_data_type")
        
        server = Server(**self.valid_data)
        server.ip_address = "samesasdaas"
        
        with self.assertRaises(ValidationError):
            server.save()
            
        logger.info("Test Passed: test_ip_address_incorrect_data_type")
            
    def test_wrong_ip_address_with_port(self):
        """
        Ensure that a server cannot be saved with an IP address that includes a port number.
        """
        logger.info("Starting test: test_wrong_ip_address_with_port")
        
        server = Server(**self.valid_data)
        server.ip_address = "10.0.0.1:8808"
        with self.assertRaises(ValidationError):
            server.save()
            
        logger.info("Test passed: test_wrong_ip_address_with_port")
            
    def test_ip_address_is_unique(self):
        """
        Ensure that IP addresses are unique.
        Creating two servers with the same IP address should raise an ValidationError.
        """
        logger.info("Starting test: test_ip_address_is_unique")
        
        Server.objects.create(**self.valid_data)
        with self.assertRaises(ValidationError):
            Server.objects.create(**self.valid_data)
            
        logger.info("Test Passed: test_ip_address_is_unique")
            
    def test_ip_address_edge_cases(self):
        """
        Test edge cases for IP addresses, including the maximum and minimum values for IPv4.
        """
        logger.info("Starting test: test_ip_address_edge_cases")
        
        server = Server(**self.valid_data)

        server.ip_address = "255.255.255.255"
        server.save()

        server.ip_address = "0.0.0.0"
        server.save()

        server.ip_address = "999.999.999.999"
        with self.assertRaises(ValidationError):
            server.save()
            
        logger.info("Test Passed: test_ip_address_edge_cases")
            
    def test_port_is_required(self):
        """
        Ensure that a server cannot be saved without a port.
        """
        logger.info("Starting test: test_port_is_required")
        
        server = Server(**self.valid_data)
        server.port = None
        with self.assertRaises(ValidationError):
            server.save()
            
        logger.info("Test passed: test_port_is_required")
            
    def test_port_edge_cases(self):
        """
        Test edge cases for the port field.
        Ensure that ports are within the valid range (1-65535).
        """
        logger.info("Starting test: test_port_edge_cases")
        
        server = Server(**self.valid_data)

        server.port = 80
        server.save()

        server.port = 70000
        with self.assertRaises(ValidationError):
            server.save()

        server.port = -1
        with self.assertRaises(ValidationError):
            server.save()
            
        logger.info("Test passed: test_port_edge_cases")
            
    def test_port_incorrect_data_type(self):
        """
        Ensure that a server cannot be saved with an incorrect data type for the port.
        """
        logger.info("Starting test: test_port_incorrect_data_type")
        
        server = Server(**self.valid_data)
        server.port = "dddddd"
        with self.assertRaises(ValidationError):
            server.save()
            
        logger.info("Test passed: test_port_incorrect_data_type")
            
    def test_invalid_location_type_raises_error(self):
        """
        Ensure that saving a server with an invalid location type raises an error.
        The `location` should be a string, so using an integer will raise a TypeError.
        """   
        logger.info("Starting test: test_invalid_location_type_raises_error")
              
        with self.assertRaises(ValidationError):
            Server.objects.create(
                name='Artur',
                ip_address=IP_ADDRESS,
                port=8080,
                location=123,
                user=self.user,
                trusty=True,
                available=True
            )
        
        logger.info("Test passed: test_invalid_location_type_raises_error")
            
    def test_location_max_length(self):
        """
        Ensure that the `location` field is truncated to 100 characters if it's too long.
        """
        logger.info("Starting test: test_location_max_length")
        
        server = Server(**self.valid_data)
        server.location = 'A' * 105  
        server.save()
        self.assertEqual(len(server.location), 100)
        
        logger.info("Test passed: test_location_max_length")
        
    def test_empty_name_raises_error(self):
        """
        Ensure that saving a server with an empty `location` raises an error.
        """
        logger.info("Starting test: test_empty_name_raises_error")
            
        with self.assertRaises(ValidationError):
            server = Server.objects.create(
            name='Artur',
            ip_address=IP_ADDRESS,
            port=8080,
            location='',
            user=self.user,
            trusty=True,
            available=True
        )
        
        with self.assertRaises(ValidationError):
            Server.objects.create(
                name='Artur',
                ip_address=IP_ADDRESS,
                port=8080,
                location=None,
                user=self.user,
                trusty=True,
                available=True
            )
            
        logger.info("Test passed: test_empty_name_raises_error")
    
    def test_user_incorrect_data_type(self):
        """
        Ensure that a server cannot be saved with an incorrect data type for the `user` field.
        """
        logger.info("Starting test: test_user_incorrect_data_type")
        
        invalid_values = ["string", 123, {"invalid": "dict"}, ["list"]]
        server = Server(**self.valid_data)
        for value in invalid_values:
            server = Server(**self.valid_data)
            with self.assertRaises(ValueError):
                server.user = value
                
        logger.info("Test passed: test_user_incorrect_data_type")
            
    def test_user_deletion_sets_user_to_null(self):
        """
        Test that deleting a user sets the `user` field to null in the `Server` model.
        """
        logger.info("Starting test: test_user_deletion_sets_user_to_null")
        
        
        testUser = get_user_model().objects.create_user(
                                            username='testuser2',
                                            password='testD.pass123',
                                            email='email5@example.com',
                                            first_name='testuser',
                                            last_name='Czwarty',
                                            )
        
        server = Server.objects.create(
            name='Artur',
            ip_address=IP_ADDRESS,
            port=8080,
            location='Bartniki',
            user=testUser,
            trusty=True,
            available=True
        )

        self.assertEqual(server.user, testUser)
        
        testUser.delete()

        server.refresh_from_db()

        self.assertIsNone(server.user)
        
        logger.info("Test passed: test_user_deletion_sets_user_to_null")
        
    def test_trusty_incorrect_data_type(self):
        """
        Tests that a ValidationError is raised when a Server object is created
        with an invalid data type for the `trusty` field.

        The `trusty` field is expected to be a boolean value, but a string is provided.
        The `save` method should validate this and raise a ValidationError.
        """
        logger.info("Starting test: test_trusty_incorrect_data_type")
        
        server = Server(**self.valid_data)
        server.trusty = "dddddd"
        with self.assertRaises(ValidationError):
            server.save()
            
        logger.info("Test pass: test_trusty_incorrect_data_type")
            
    def test_available_incorrect_data_type(self):
        """
        Tests that a ValidationError is raised when a Server object is created
        with an invalid data type for the `available` field.

        The `available` field is expected to be a boolean value, but a string is provided.
        The `save` method should validate this and raise a ValidationError.
        """
        logger.info("Starting test: test_available_incorrect_data_type")
        
        server = Server(**self.valid_data)
        server.available = "dddddd"
        with self.assertRaises(ValidationError):
            server.save()
            
        logger.info("Test pass: test_available_incorrect_data_type")
            
    def test_trusty_and_available_defaults(self):
        """
        Tests that the `trusty` and `available` fields of a Server object
        default to False when the object is created.

        This ensures that new Server objects are initialized with the expected default values
        for these fields.
        """
        logger.info("Starting test: test_trusty_and_available_defaults")
        
        server = Server.objects.create(
            name='TestServer',
            ip_address=IP_ADDRESS,
            port=8080,
            location='Datacenter',
            user=self.user
        )
        self.assertFalse(server.trusty)
        self.assertFalse(server.available)
        
        logger.info("Test passed: test_trusty_and_available_defaults")
            
    def test_delete_server(self):
        """
        Tests successful deletion of a Server instance.

        This test verifies the following:
        1. A Server object can be created and saved.
        2. The number of Server objects in the database is incremented to 1.
        3. After deleting the server, the object is no longer found using the IP address.
        4. The number of Server objects in the database is decremented to 0.
        """
        
        logger.info("Starting test: test_delete_server")
        
        server = Server(**self.valid_data)
        server.save()
        
        self.assertEqual(Server.objects.count(), 1, "should be one object" )

        server.delete()
        self.assertFalse(Server.objects.filter(ip_address=IP_ADDRESS).exists(),"should be False")
        
        self.assertEqual(Server.objects.count(), 0, "should be no one object" )
        
        logger.info("Test passed: test_delete_server")


class SessionModelTest(TestCase):
    
    def setUp(self):
        """
        Create sample user and server objects for testing purposes.
        """
   
        self.user = get_user_model().objects.create_user(
                                                username='testuser',
                                                password='testD.pass123',
                                                email='email@example.com',
                                                first_name='testuser',
                                                last_name='Czwarty',
                                                )
        self.user_1 = get_user_model().objects.create_user(
                                                username='testuser1',
                                                password='testD.pass123',
                                                email='email2@example.com',
                                                first_name='testuser',
                                                last_name='Czwarty',
                                                )
        self.server = Server.objects.create(
            name='TestServer',
            ip_address=IP_ADDRESS,
            port=8080,
            location='Datacenter',
            user=self.user,
            trusty=True,
            available=True
        )
           
        self.server_1 = Server.objects.create(
            name='TestServer1',
            ip_address='127.0.0.1',
            port=8080,
            location='Datacenter',
            user=self.user,
            trusty=True,
            available=True
        )
    
    def test_create_valid_session(self):
        """
        Test that a Session object can be created with valid data.
        - Creates a session with a user and server.
        - Asserts that the session has a primary key (pk) after creation.
        - Asserts that the session ID has a length of 32 characters.
        - Asserts that the session ID format matches the regular expression for a hexadecimal string.
        - Asserts that the created time is close to the current time (within 1 second).
        """
        logger.info("Starting test: test_create_valid_session")
        
        session = Session.objects.create(user=self.user,server=self.server)
        self.assertIsNotNone(session.pk)
        self.assertEqual(len(session.sessionId), 32) 
        self.assertRegex(session.sessionId, r"^[0-9a-f]{32}$")
        self.assertAlmostEqual(session.created, timezone.now(), delta=timezone.timedelta(seconds=1))
        
        logger.info("Test passed: test_create_valid_session")
        
        
    def test_generate_unique_session_id(self):
        """
        Tests that the `generate_valid_session_id` method generates unique session IDs.

        - Creates two sessions with different users and servers.
        - Asserts that the generated session IDs for each session are not equal, demonstrating uniqueness.
        """
        logger.info("Starting test: test_generate_unique_session_id")
        
        session1 = Session.objects.create(user=self.user,server=self.server)
        session2 = Session.objects.create(user=self.user_1,server=self.server_1) 
        self.assertNotEqual(session1.sessionId, session2.sessionId)
        
        logger.info("Test passed: test_generate_unique_session_id")
        
    def test_session_save_method_generates_session_id(self):
        """
        Tests that the `save` method automatically generates a session ID if it's not already set.

        - Creates a session object with a user and server but without a session ID.
        - Saves the session.
        - Asserts that the session now has a non-null session ID and that the length is 32 characters.
        """
        logger.info("Starting test: test_session_save_method_generates_session_id")
        
        session = Session(user=self.user, server=self.server)
        session.save()
        self.assertIsNotNone(session.sessionId)
        self.assertEqual(len(session.sessionId), 32)
        
        logger.info("Test passed: test_session_save_method_generates_session_id")
        
    def test_create_session_id_for_the_same_user(self):
        """
        Tests that a ValidationError is raised when creating multiple sessions for the same user.

        - Creates a session for the current user.
        - Attempts to create another session with the same user and server.
        - Asserts that a ValidationError is raised, indicating that a session already exists for the user.
        """
        logger.info("Starting test: test_create_session_id_for_the_same_user")
        
        Session.objects.create(user=self.user,server=self.server)
        with self.assertRaises(ValidationError):
            Session.objects.create(user=self.user,server=self.server_1) 
            
        logger.info("Test passed: test_create_session_id_for_the_same_user")
            
    def test_create_session_id_for_none_user(self):
        """
        Tests that a ValidationError is raised when trying to create a session with a None user.

        - Attempts to create a session with a `None` value for the `user` field.
        - Asserts that a ValidationError is raised, indicating that the user field cannot be empty.
        """
        logger.info("Starting test: test_create_session_id_for_none_user")
        
        with self.assertRaises(ValidationError):
            Session.objects.create(user=None,server=self.server) 
            
        logger.info("Test passed: test_create_session_id_for_none_user")
            
    def test_create_session_id_incorrect_data_type_user(self):
        """
        Tests that a ValueError is raised when trying to create a session with an incorrect data type for the `user` field.

        - Attempts to create a session with an empty string for the `user` field.
        - Asserts that a ValueError is raised, indicating that the `user` field must be a `User` instance.
        """
        logger.info("Starting test: test_create_session_id_incorrect_data_type_user")
        with self.assertRaises(ValueError):
            Session.objects.create(user='',server=self.server)
            
        logger.info("Test passed: test_create_session_id_incorrect_data_type_user")
            
    def test_user_delete_cascades_to_session(self):
        """
        Tests that deleting a user also deletes the related session (on_delete.CASCADE).

        - Creates a user and a session associated with that user.
        - Verifies that one session object exists before deletion.
        - Deletes the user.
        - Asserts that attempting to retrieve the session by its primary key raises an `ObjectDoesNotExist` exception, indicating successful cascade deletion.
        """
        logger.info("Starting test: test_user_delete_cascades_to_session")
        

        user = get_user_model().objects.create_user(
                                    username='testuserDel',
                                    password='testD.pass123',
                                    email='email46@example.com',
                                    first_name='testuser',
                                    last_name='Czwarty',
                                    )
        
        session = Session.objects.create(user=user,server=self.server)
        
        self.assertEqual(Session.objects.count(), 1, "should be one object" )
        
        user.delete() 

        with self.assertRaises(ObjectDoesNotExist):
            Session.objects.get(pk=session.pk)
            
        logger.info("Test passed: test_user_delete_cascades_to_session")
            
    def test_invalid_session_id_format(self):
        """
        Tests that a ValidationError is raised when creating a session with an invalid session ID format.

        - Creates a session object.
        - Manually sets an invalid session ID on the session object.
        - Attempts to save the session object (triggers validation).
        - Asserts that a ValidationError is raised, indicating that the session ID format is invalid.
        """
        
        logger.info("Starting test: test_invalid_session_id_format")
        
        session = Session.objects.create(user=self.user,server=self.server)
        session.sessionId = 'invalidsessionid' 
        with self.assertRaises(ValidationError):
            session.save()
            
        logger.info("Test passed: test_invalid_session_id_format")
            
    def test_unique_session_id (self):
        """
        Tests that a ValidationError is raised when trying to create multiple sessions with the same session ID.

        - Generates a unique session ID.
        - Creates a session with the generated session ID.
        - Attempts to create another session with the same session ID.
        - Asserts that a ValidationError is raised, indicating that the session ID already exists.
        """
        logger.info("Starting test: test_unique_session_id")
        
        testSessionId=uuid.uuid4().hex
        Session.objects.create(user=self.user, sessionId=testSessionId, server=self.server)
        with self.assertRaises(ValidationError):
            Session.objects.create(user=self.user, sessionId=testSessionId, server=self.server)
            
        logger.info("Test passed: test_unique_session_id")
            
    def test_create_with_none_session_id (self):
        """
        Tests that a session is created automatically with a unique session ID when the `sessionId` field is not provided.

        - Creates a session with a `None` value for the `sessionId` field.
        - Asserts that the session is created successfully and has a non-null session ID.
        """
        logger.info("Starting test: test_create_with_none_session_id")
        
        session = Session.objects.create(user=self.user, sessionId=None, server=self.server)
        self.assertIsNotNone(session.sessionId)
        
        logger.info("Test passed: test_create_with_none_session_id")
        
    def test_create_with_empty_string_session_id (self):
        """
        Tests that a session is created automatically with a unique session ID when the `sessionId` field is an empty string.

        - Creates a session with an empty string for the `sessionId` field.
        - Asserts that the session is created successfully and has a non-null session ID.
        """
        logger.info("Starting test: test_create_with_empty_string_session_id")
        
        session = Session.objects.create(user=self.user, sessionId='', server=self.server)
        self.assertIsNotNone(session.sessionId)
        
        logger.info("Test passed: test_create_with_empty_string_session_id")
        
    def test_edit_session_id(self):
        """
        Tests that modifying the session ID after object creation raises a ValidationError.

        - Creates a session.
        - Attempts to modify the session's `sessionId` attribute.
        - Asserts that saving the session raises a ValidationError, indicating that session ID modification is not allowed.
        """
        logger.info("Starting test: test_edit_session_id")
        
        testSessionId=uuid.uuid4().hex
        session = Session.objects.create(user=self.user,server=self.server)
        session.sessionId = testSessionId
        with self.assertRaises(ValidationError):
            session.save()
            
        logger.info("Test passed: test_edit_session_id")
            
    def test_create_session_id_for_the_same_server(self):
        """
        Tests that a ValidationError is raised when creating a session for a different user on the same server (incorrect behavior).**

        - Creates a session for the current user (`user`).
        - Attempts to create another session with a different user (`user_1`) but the same server.
        - Asserts that a ValidationError is raised, indicating that a session already exists for the server.
        """
       
        logger.info("Starting test: test_create_session_id_for_the_same_server")
        
        Session.objects.create(user=self.user,server=self.server)
        with self.assertRaises(ValidationError):
            Session.objects.create(user=self.user_1,server=self.server)
            
        logger.info("Test passed: test_create_session_id_for_the_same_server")
            
    def test_invalid_server_untrusted(self):
        """
        Tests that a ValidationError is raised when creating a session for an untrusted server.

        - Sets the `trusty` field of the server object to `False`, marking it as untrusted.
        - Attempts to create a session with this untrusted server.
        - Asserts that a ValidationError is raised, indicating that sessions cannot be created for untrusted servers.
        """
        logger.info("Starting test: test_invalid_server_untrusted")
        
        self.server.trusty = False
        self.server.save()
        session = Session(user=self.user,server=self.server)
        with self.assertRaises(ValidationError):
            session.save()
            
        logger.info("Test passed: test_invalid_server_untrusted")
            
    def test_invalid_server_unavailable(self):
        """
        Tests that a ValidationError is raised when creating a session for an unavailable server.

        - Sets the `available` field of the server object to `False`, marking it as unavailable.
        - Attempts to create a session with this unavailable server.
        - Asserts that a ValidationError is raised, indicating that sessions cannot be created for unavailable servers.
        """
        logger.info("Starting test: test_invalid_server_unavailable")
        
        self.server.available = False
        self.server.save()
        session = Session(user=self.user,server=self.server)
        with self.assertRaises(ValidationError):
            session.save()
            
        logger.info("Test passed: test_invalid_server_unavailable")
            
    def test_invalid_server_untrusted_and_unavailable(self):
        """
        Tests that a ValidationError is raised when creating a session for a server that is both untrusted and unavailable.

        - Sets the `trusty` field of the server object to `False`, marking it as untrusted.
        - Sets the `available` field of the server object to `False`, marking it as unavailable.
        - Attempts to create a session with this untrusted and unavailable server.
        - Asserts that a ValidationError is raised, indicating that sessions cannot be created for servers with both trust and availability issues.
        """
        logger.info("Starting test: test_invalid_server_untrusted_and_unavailable")
        
        self.server.trusty = False
        self.server.available = False
        self.server.save()
        session = Session(user=self.user, server=self.server)
        with self.assertRaises(ValidationError):
            session.save()
            
        logger.info("Test passed: test_invalid_server_untrusted_and_unavailable")
            
    def test_server_delete_cascades_to_session(self):
        """
        Tests that deleting a server also deletes its associated sessions (on_delete.CASCADE).

        - Creates a server with `on_delete.CASCADE` behavior.
        - Creates a session associated with the server.
        - Verifies that one session object exists before deletion.
        - Deletes the server.
        - Asserts that attempting to retrieve the session by its primary key raises an `ObjectDoesNotExist` exception, indicating successful cascade deletion.
        """
        logger.info("Starting test: test_server_delete_cascades_to_session")
        
        server = Server.objects.create(
            name='TestServer2',
            ip_address='196.0.0.1',
            port=8080,
            location='Datacenter',
            user=self.user,
            trusty=True,
            available=True
        )
        
        session = Session.objects.create(user=self.user,server=server)
        
        self.assertEqual(Session.objects.count(), 1, "should be one object" )
        
        server.delete() 

        with self.assertRaises(ObjectDoesNotExist):
            Session.objects.get(pk=session.pk)
            
        logger.info("Test passed: test_server_delete_cascades_to_session")
            
    def test_create_session_id_with_none_server(self):
        """
        Tests that a ValidationError is raised when creating a session without specifying a server.

        - Attempts to create a session with a `None` value for the `server` field.
        - Asserts that a ValidationError is raised, indicating that a server is required for session creation.
        """
        logger.info("Starting test: test_create_session_id_with_none_server")
        
        with self.assertRaises(ValidationError):
            Session.objects.create(user=self.user,server=None)
            
        logger.info("Test passed: test_create_session_id_with_none_server")
            
    def test_create_session_id_with_incorrect_format_server(self):
        """
        Tests that a ValueError is raised when creating a session with an invalid server format (empty string in this case).

        - Attempts to create a session with an empty string for the `server` field.
        - Asserts that a ValueError is raised, indicating that the server format is invalid.
        """
        logger.info("Starting test: test_create_session_id_with_incorrect_format_server")
        
        with self.assertRaises(ValueError):
            Session.objects.create(user=self.user,server='')
            
        logger.info("Test passed: test_create_session_id_with_incorrect_format_server")
            
    def test_invalid_expiration_time_too_short(self):
        """
        Tests that a ValidationError is raised when setting a session expiration time shorter than the minimum allowed duration.

        - Retrieves the minimum allowed session expiration time from settings (e.g., `settings.MIN_EXPIRATION_HOURS`).
        - Creates a session object with an expiration time one hour less than the minimum.
        - Attempts to save the session.
        - Asserts that a ValidationError is raised, indicating that the expiration time is too short.
        """
        logger.info("Starting test: test_invalid_expiration_time_too_short")
        
        expires = timezone.now() + timezone.timedelta(hours=settings.MIN_EXPIRATION_HOURS - 1)
        session = Session(user=self.user,server=self.server)
        session.expires = expires
        with self.assertRaises(ValidationError):
            session.save()
            
        logger.info("Test passed: test_invalid_expiration_time_too_short")
            
    def test_invalid_expiration_time_too_long(self):
        """
        Tests that a ValidationError is raised when setting a session expiration time exceeding the maximum allowed duration.

        - Retrieves the maximum allowed session expiration time from settings (e.g., `settings.MAX_EXPIRATION_HOURS`).
        - Creates a session object with an expiration time one hour more than the maximum.
        - Attempts to save the session.
        - Asserts that a ValidationError is raised, indicating that the expiration time is too long.
        """
        logger.info("Starting test: test_invalid_expiration_time_too_long")
        
        expires = timezone.now() + timezone.timedelta(hours=settings.MAX_EXPIRATION_HOURS + 1)
        session = Session(user=self.user,server=self.server)
        session.expires = expires
        with self.assertRaises(ValidationError):
            session.save()
        
        logger.info("Test passed: test_invalid_expiration_time_too_long")
            
    def test_session_expired(self):
        """
        Tests that a ValidationError is raised when creating a session with an already expired expiration time.

        - Creates an expiration time one hour in the past (representing an expired session).
        - Creates a session object with the expired expiration time.
        - Attempts to save the session.
        - Asserts that a ValidationError is raised, indicating that the session is already expired and cannot be saved.
        """
        logger.info("Starting test: test_session_expired")
        
        expires = timezone.now() - timezone.timedelta(hours=1)
        session = Session(user=self.user,server=self.server)
        session.expires = expires
        with self.assertRaises(ValidationError):
            session.save()
            
        logger.info("Test Passed: test_session_expired")
            
    def test_valid_expiration_min_boundary(self):
        """
        Tests that creating a session with the minimum allowed expiration time is successful.

        - Retrieves the minimum allowed session expiration time from settings (e.g., `settings.MIN_EXPIRATION_HOURS`).
        - Creates an expiration time at the minimum allowed boundary.
        - Creates a session object with the minimum allowed expiration time.
        - Saves the session without raising an error.
        - (Optional) Logs test start and pass messages (these are typically not included in unit tests).
        """
        
        logger.info("Starting test: test_valid_expiration_min_boundary")
        expires = timezone.now() + timezone.timedelta(hours=settings.MIN_EXPIRATION_HOURS)
        session = Session(user=self.user, server=self.server, expires=expires)
        session.save() 
        
        logger.info("Test passed: test_valid_expiration_min_boundary")

    def test_valid_expiration_max_boundary(self):
        """
        Tests that creating a session with the maximum allowed expiration time is successful.

        - Retrieves the maximum allowed session expiration time from settings (e.g., `settings.MAX_EXPIRATION_HOURS`).
        - Creates an expiration time at the maximum allowed boundary.
        - Creates a session object with the maximum allowed expiration time.
        - Saves the session without raising an error.
        """
        logger.info("Starting test: test_valid_expiration_max_boundary")
        
        expires = timezone.now() + timezone.timedelta(hours=settings.MAX_EXPIRATION_HOURS)
        session = Session(user=self.user, server=self.server, expires=expires)
        session.save()
        
        logger.info("Test passed: test_valid_expiration_max_boundary")
        
    def test_create_session_with_null_expires(self):
        """
        Tests that a ValidationError is raised when creating a session with a null `expires` field.

        - Creates a session object with a `None` value for the `expires` field.
        - Attempts to save the session.
        - Asserts that a ValidationError is raised, indicating that an expiration time is required for a session.
        """
        logger.info("Starting test: test_create_session_with_null_expires")
        
        session = Session(user=self.user, server=self.server, expires=None)
        with self.assertRaises(ValidationError):
            session.save()
            
        logger.info("Test passed: test_create_session_with_null_expires")
            
    def test_create_session_with_null_created(self):
        """
        Tests that a session is created with the current time when the `created` field is null.

        - Creates a session object with a `None` value for the `created` field.
        - Saves the session.
        - Asserts that the `created` field of the saved session is approximately equal to the current time within a one-second tolerance (due to potential timing differences).
        """
        logger.info("Starting test: test_create_session_with_null_created")
        
        session = Session(user=self.user, server=self.server, created=None)
        session.save()
        self.assertAlmostEqual(session.created, timezone.now(), delta=timezone.timedelta(seconds=1))
        
        logger.info("Test passed: test_create_session_with_null_created")
        
    def test_valid_incorrect_time_creation(self):
        """
        Tests that a ValidationError is raised when creating a session with a future `created` time.

        - Creates a session object with a `created` field set one hour in the future.
        - Attempts to save the session.
        - Asserts that a ValidationError is raised, indicating that sessions cannot be created with timestamps in the future.
        """
        logger.info("Starting test: test_valid_incorrect_time_creation")
        
        created = timezone.now() + timezone.timedelta(hours=1)
        session = Session(user=self.user, server=self.server, created=created)

        with self.assertRaises(ValidationError):
            session.save()
            
        logger.info("Test passed: test_valid_incorrect_time_creation")
    
    def test_expires_is_aware(self):
        """
        Tests that the `expires` field of a session is timezone-aware.

        - Creates a session object.
        - Asserts that the `expires` field is timezone-aware using `timezone.is_aware`.
        """
        logger.info("Starting test: test_expires_is_aware")
        
        session = Session(user=self.user, server=self.server)
        
        self.assertTrue(timezone.is_aware(session.expires),"Expires should be timezone-aware.")
        
        logger.info("Test passed: test_expires_is_aware")
        
    def test_created_is_aware(self):
        """
        Tests that the `created` field of a session is timezone-aware.

        - Creates a session object.
        - Saves the session.
        - Asserts that the `created` field is timezone-aware using `timezone.is_aware`.
        """
        
        logger.info("Starting test: test_created_is_aware")
        
        session = Session(user=self.user, server=self.server)
        session.save()
        
        self.assertTrue(timezone.is_aware(session.created),"Created should be timezone-aware.")
        
        logger.info("Test passed: test_created_is_aware")
            
    def test_delete_session(self):
        """
        Tests that deleting a session works as expected.

        - Creates a session object.
        - Saves the session.
        - Verifies that one session object exists before deletion.
        - Deletes the session.
        - Verifies that no sessions exist for the user after deletion (using `filter` and `exists`).
        - Verifies that the total number of session objects is zero after deletion.
        """
        
        logger.info("Starting test: test_delete_server")
        
        server = Session(user=self.user,server=self.server)
        server.save()
        
        self.assertEqual(Session.objects.count(), 1, "should be one object" )

        server.delete()
        self.assertFalse(Session.objects.filter(user=self.user).exists(),"should be False")
        
        self.assertEqual(Session.objects.count(), 0, "should be no one object" )
        
        logger.info("Test passed: test_delete_session")
        
        
class TemporaryTokenTestCase(TestCase):
    def setUp(self):
        """Set up test data for TemporaryToken model."""
        
        self.user = get_user_model().objects.create_user(
                                                username='testuser',
                                                password='testD.pass123',
                                                email='email@example.com',
                                                first_name='testuser',
                                                last_name='Czwarty',
                                                )

        self.server = Server.objects.create(
            name='TestServer',
            ip_address=IP_ADDRESS,
            port=8080,
            location='Datacenter',
            user=self.user,
            trusty=True,
            available=True
        )
        
        self.session = Session.objects.create(user=self.user,server=self.server)
        
    def test_generate_temporary_token(self):
        """Test token generation logic."""
        logger.info("Starting test: test_generate_temporary_token")
        token = TemporaryToken().generate_temporary_token()
        self.assertEqual(len(token), 43)
        
        logger.info("Test Passed: test_generate_temporary_token")
        
    def test_token_creation(self):
        """Test creating a TemporaryToken instance."""
        logger.info("Starting test: test_token_creation")
        token = TemporaryToken.objects.create(session=self.session, path = "testPath")
        self.assertIsNotNone(token.token)
        self.assertFalse(token.is_expired())
        self.assertGreaterEqual(token.expires_at, timezone.now())
        
        logger.info("Test Passed: test_token_creation")
        
    def test_is_expired(self):
        """Test the is_expired method."""
        logger.info("Starting test: test_is_expired")
        token = TemporaryToken.objects.create(session=self.session, path = "testPath")
        self.assertFalse(token.is_expired())

        # Simulate token expiration
        with self.assertRaises(ValidationError) as context:
            token.expires_at = timezone.now() - timedelta(minutes=1)
            token.save()
        self.assertIn("Token has expired.", str(context.exception))
        
        logger.info("Test Passed: test_is_expired")
        
    def test_creation_no_session(self):
        """Test validation error when no session is assigned."""
        logger.info("Starting test: test_creation_no_session")
        
        with self.assertRaises(ValidationError) as context:
            token = TemporaryToken.objects.create(session=None, path = "testPath")
        self.assertIn("no session to generate token", str(context.exception))
        
        logger.info("Test Passed: test_creation_no_session")
        
    def test_creation_token_expired(self):
        """Test validation error when token is expired."""
        logger.info("Starting test: test_creation_token_expired")
        
        with self.assertRaises(ValidationError) as context:
            token = TemporaryToken.objects.create(session=self.session, expires_at=timezone.now() - timedelta(minutes=1), path = "testPath")
        self.assertIn("Token has expired.", str(context.exception))
        
        logger.info("Test Passed: test_creation_token_expired")
        
    def test_creation_created_after_expiry(self):
        """Test validation error when created_at is after expires_at."""
        logger.info("Starting test: test_creation_created_after_expiry")
        
        with self.assertRaises(ValidationError) as context:
            token = TemporaryToken.objects.create(session=self.session, created_at=timezone.now() + timedelta(minutes=10), path = "testPath")
        self.assertIn("Created time seems unexpected. Please check system time.", str(context.exception))
        
        logger.info("Test Passed: test_creation_created_after_expiry")

           


        

     