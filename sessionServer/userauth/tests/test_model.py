from django.test import TestCase
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.utils import timezone
from unittest.mock import patch, call
from django.contrib.auth import authenticate
from userauth.models import User,UsedToken, handle_redis_connected, handle_redis_connection_failed
import logging

logger = logging.getLogger("test_logger")


class UserModelTest(TestCase):

    def setUp(self):
        """
        Setting up user data to be used in the tests.
        """
        logger.info("Setting up user data for testing.")
        self.user_data = {
            "first_name": "Czeslaw",
            "last_name": "Czwarty",
            "email": "czeslaw_Czwarty@example.com",
            "username": "Czeslaw",
            'password':'passsUda24.a3@!word'
        }
        
    def tearDown(self):
        """
        Clearing allowed users after each test.
        """
        logger.info("Tearing down test: Clearing allowed users.")
        User.clear_allowed_users()
        super().tearDown()
 
    def test_create_user_successfully(self):
        """
        Test that a user is created with valid data.
        """
        logger.info("Starting test: test_create_user_successfully")
        user = User.objects.create_user(**self.user_data)

        logger.debug(f"Created user: {user.username}")
        self.assertEqual(user.username, self.user_data["username"])
        self.assertEqual(str(user), self.user_data["username"])
        self.assertEqual(user.email, self.user_data["email"])
        self.assertTrue(user.check_password(self.user_data["password"]))
        self.assertTrue(user.is_active)
        
        user = authenticate(username=self.user_data["email"], password=self.user_data["password"])
        self.assertTrue(user)
        
        user = authenticate(username=self.user_data["username"], password=self.user_data["password"])
        self.assertTrue(user)
        
        self.assertTrue(User.is_user_allowed(user.username))
        
        logger.info("Test passed: test_create_user_successfully")
        
    def test_create_user_with_short_password(self):
        """
        Test that creating a user with a short password raises a ValidationError.
        """
        logger.info("Starting test: test_create_user_with_short_password")
        self.user_data["password"] = "short"
        with self.assertRaises(ValueError) as context:
            User.objects.create_user(**self.user_data)
        logger.debug(f"Raised exception: {context.exception}")
        self.assertIn("Password validation error", str(context.exception))
        
        self.assertFalse(User.is_user_allowed(self.user_data["username"]))
        
        logger.info("Test passed: test_create_user_with_short_password")

    def test_create_user_without_password(self):
        """
        Test that creating a user without a password raises ValueError.
        """
        logger.info("Starting test: test_create_user_without_passwor")
        self.user_data.pop("password")
        with self.assertRaises(ValueError) as context:
            User.objects.create_user(**self.user_data)
        logger.debug(f"Raised exception: {context.exception}")
        self.assertEqual(str(context.exception), "The password field cannot be empty.")
        
        logger.info("Test passed: test_create_user_without_passwor")
        
    def test_create_user_common_password(self):
        """
        Test that creating a user with a common password raises ValueError.
        """
        logger.info("Starting test: test_create_user_common_password")
        self.user_data["password"] = "password"
        with self.assertRaises(ValueError) as context:
            User.objects.create_user(**self.user_data)
        logger.debug(f"Raised exception: {context.exception}")  
        logger.info("Test passed: test_create_user_common_password")
        
    def test_create_user_number_password(self):
        """
        Test that creating a user with a purely numeric password raises ValueError.
        """
        logger.info("Starting test: test_create_user_number_password")
        self.user_data["password"] = "1232354898752566"
        with self.assertRaises(ValueError) as context:
            User.objects.create_user(**self.user_data)
            
        logger.info("Test passed: test_create_user_number_password")
            
    def test_invalid_username(self):
        """
        Test that creating a user with an invalid username raises ValueError.
        """
        logger.info("Starting test: test_invalid_username")
        self.user_data["username"] = "Rysz`&#ard"
        with self.assertRaises(ValueError) as context:
            User.objects.create_user(**self.user_data)
        logger.debug(f"Raised exception: {context.exception}")
            
        logger.info("Test passed: test_invalid_username")
        
    def test_invalid_username_2(self):
        """
        Test that creating a user with another invalid username raises ValueError.
        """
        logger.info("Testing user creation with an invalid username containing '@'.")
        self.user_data["username"] = "Ryszrd@"
        with self.assertRaises(ValueError) as context:
            User.objects.create_user(**self.user_data)
        logger.debug(f"Raised exception: {context.exception}")
        
        logger.info("Test passed: test_invalid_username")

  
    def test_existing_username(self):
        """
        Test that creating a user with an existing username raises ValueError.
        """
        logger.info("Starting test: test_existing_username")
        User.objects.create_user(**self.user_data)

        with self.assertRaises(ValueError):
            User.objects.create_user(**self.user_data)
            
        logger.info("Test passed: test_existing_username")
            
    def test_existing_email(self):
        """
        Test that creating a user with an existing email raises ValueError.
        """
        logger.info("Starting test: test_existing_email")
        User.objects.create_user(**self.user_data)

        with self.assertRaises(ValueError):
            self.user_data["username"] = "Ryszard"
            User.objects.create_user(**self.user_data)
       
        logger.info("Test passed: test_existing_email")
            
    def test_invalid_email(self):
        """
        Test that creating a user with an invalid email raises ValidationError.
        """
        logger.info("Starting test: test_invalid_email")
        
        self.user_data["email"] = "Ryszard.Lwie"
        with self.assertRaises(ValidationError) as context:
            User.objects.create_user(**self.user_data)
        self.assertIn("Enter a valid email address", str(context.exception))
        logger.debug(f"Raised exception: {context.exception}")
        logger.info("Test passed: test_invalid_email")
        
    def test_get_full_name(self):
        """
        Test that the get_full_name property returns the correct full name.
        """
        logger.info("Testing get_full_name property.")
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.get_full_name, "Czeslaw Czwarty")
        
    def test_username_change_updates_redis(self):
        """
        Test that changing the username updates allowed_users in Redis.
        """
        logger.info("Starting test: test_username_change_updates_redis")
        with patch.object(User, 'remove_allowed_user') as mock_remove, \
             patch.object(User, 'add_allowed_user') as mock_add:
            user = User.objects.create_user(**self.user_data)
            user.username = "NewUsername"
            user.save()
            
            expected_add_calls = [call("Czeslaw"), call("NewUsername")]

            # Ensure remove_allowed_user and add_allowed_user were called
            mock_remove.assert_called_once_with("Czeslaw")
            mock_add.assert_has_calls(expected_add_calls, any_order=False)
            
            self.assertEqual(mock_add.call_count , len(expected_add_calls))
            
            self.assertTrue(User.is_user_allowed("NewUsername"))
            self.assertFalse(User.is_user_allowed("Czeslaw"))
            
        logger.info("Test passed: test_username_change_updates_redis")
            
    def test_load_allowed_users_on_redis_connect(self):
        """
        Test that load_allowed_users is called when Redis connects.
        """
        logger.info("Starting test: test_load_allowed_users_on_redis_connect")
        with patch.object(User, 'load_allowed_users') as mock_load:
            User.allowed_users.redis_connected(False)
            handle_redis_connected(sender=None)
            mock_load.assert_called_once()
            self.assertTrue(User.allowed_users.check_if_redis_connected())
            
        logger.info("Test passed: test_load_allowed_users_on_redis_connect")

    def test_remove_user_from_allowed_users_on_delete(self):
        """
        Test that deleting a user removes them from allowed_users in Redis.
        """
        logger.info("Starting test: test_remove_user_from_allowed_users_on_delete")
        with patch.object(User, 'remove_allowed_user') as mock_remove:
            user = User.objects.create_user(**self.user_data)
            user.delete()
            mock_remove.assert_called_once_with("Czeslaw")
            
            self.assertFalse(User.is_user_allowed("Czeslaw"))
            
        logger.info("Test passed: test_remove_user_from_allowed_users_on_delete")
            
    def test_redis_connection_failed(self):
        """
        Test that Redis connection failure sets the connected status to False.
        """
        logger.info("Starting test: test_redis_connection_failed")
        User.allowed_users.redis_connected(True) 
        handle_redis_connection_failed(sender=None)
        self.assertFalse(User.allowed_users.check_if_redis_connected())
        
        logger.info("Test passed: test_redis_connection_failed")
        
    def test_is_user_allowed_fallback_to_db(self):
        """
        Test that is_user_allowed falls back to the database when Redis is disconnected.
        """
        logger.info("Starting test: test_is_user_allowed_fallback_to_db")
        User.allowed_users.redis_connected(False) 
        user = User.objects.create_user(**self.user_data)
        self.assertFalse(User.allowed_users.check_if_redis_connected())
        self.assertTrue(User.is_user_allowed(user.username))
        
        logger.info("Test passed: test_is_user_allowed_fallback_to_db")
        
class UsedTokenModelTest(TestCase):
    def setUp(self):
        """
        Setting up user data to be used in the tests.
        """
        logger.info("Setting up user data for testing UsedToken.")
        self.user_data = {
            "first_name": "Czeslaw",
            "last_name": "Czwarty",
            "email": "czeslaw_Czwarty@example.com",
            "username": "Czeslaw",
            'password':'passsUda24.a3@!word'
        }
        
        self.user = User.objects.create_user(**self.user_data)
        self.token = "test-token-123"
        logger.info(f"Test user created: {self.user.username}")
        logger.info(f"Test token created: {self.token}")
        
    def tearDown(self):
        """
        Clearing allowed users after each test.
        """
        logger.info("Tearing down test: Clearing allowed users.")
        User.clear_allowed_users()
        super().tearDown()

    def test_create_used_token(self):
        """
        Test creating a UsedToken instance.
        """
        logger.info("Testing UsedToken creation...")
        used_token = UsedToken.objects.create(token=self.token, user=self.user)
        expected_time = timezone.now()
        logger.info(f"UsedToken created: {used_token}")

        self.assertEqual(used_token.token, self.token, "The token should match the provided value.")
        self.assertEqual(used_token.user, self.user, "The user should match the provided user.")
        self.assertIsNotNone(used_token.used_at, "The used_at field should be automatically set.")
        self.assertAlmostEqual(used_token.used_at, expected_time, delta=timezone.timedelta(seconds=1))
        
    def test_create_used_token_without_user(self):
        """
        Test creating a UsedToken instance without a user.
        """
        logger.info("Testing UsedToken creation without a user...")
        with self.assertRaises(IntegrityError):
            UsedToken.objects.create(token=self.token, user=None)

    def test_create_used_token_without_token(self):
        """
        Test creating a UsedToken instance without a token.
        """
        logger.info("Testing UsedToken creation without a token...")
        with self.assertRaises(IntegrityError):
            UsedToken.objects.create(token=None, user=self.user)

    def test_verbose_name(self):
        """
        Test verbose_name for fields in the UsedToken model.
        """
        logger.info("Testing verbose names...")
        field_verbose_names = {
            "token": "Token",
            "user": "Użytkownik",
            "used_at": "Used At",
        }
        with self.settings(LANGUAGE_CODE="pl"):
            for field, expected_verbose_name in field_verbose_names.items():
                verbose_name = UsedToken._meta.get_field(field).verbose_name
                logger.info(f"Field '{field}' verbose name: {verbose_name}")
                self.assertEqual(verbose_name, expected_verbose_name)

    def test_help_text(self):
        """
        Test help_text for fields in the UsedToken model.
        """
        logger.info("Testing help texts...")
        field_help_texts = {
            "token": "The unique token associated with the user.",
            "user": "The user who used this token.",
            "used_at": "The timestamp when this token was used.",
        }
        for field, expected_help_text in field_help_texts.items():
            help_text = UsedToken._meta.get_field(field).help_text
            logger.info(f"Field '{field}' help text: {help_text}")
            self.assertEqual(help_text, expected_help_text)

    def test_str_method(self):
        """
        Test the __str__ method of the UsedToken model.
        """
        logger.info("Testing __str__ method...")
        used_token = UsedToken.objects.create(token=self.token, user=self.user)
        expected_str = f"Token for {self.user.username} used at {used_token.used_at}"
        logger.info(f"Expected __str__: {expected_str}")
        self.assertEqual(str(used_token), expected_str)
            
    

            

