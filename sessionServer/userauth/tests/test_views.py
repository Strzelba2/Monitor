from django.urls import reverse
from unittest.mock import patch, MagicMock
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.response import Response
from userauth.models import User, UsedToken
from django.conf import settings
from django.db.utils import IntegrityError
from oauth2_provider.models import AccessToken, RefreshToken, Application
from django.utils import timezone
from userauth.exceptions import SecretServerError
import requests
import logging
import time
from middleware.ssl_middleware import SSLMiddleware
from django.test import override_settings
import secrets
import uuid
from session.managers import LogManager
from django.http import JsonResponse
from userauth.tasks import delete_expired_tokens
from django.test import Client
from rest_framework.test import APIClient
from rest_framework.views import APIView
from django.contrib.sessions.models import Session
from django.core.signing import TimestampSigner, SignatureExpired, BadSignature
from userauth.two_factor import TwoFactor
from userauth.views import LoginAPIView
import pyotp
import json

logger = logging.getLogger("django")

def bypass_ssl_middleware(self, request, override_response=None):
    """
    Mock behavior for SSLMiddleware to bypass SSL checks during testing.
    """
    logger.debug("Bypassing SSL middleware for testing...")
    if override_response:
        logger.debug("Returning override response for SSL middleware.")
        return override_response
    return self.get_response(request)

@override_settings(SECURE_SSL_REDIRECT=False)
class LoginAPIViewTest(APITestCase):
    
    def setUp(self):
        """
        Set up test data, including a test user and an OAuth2 application.
        Also, clears the log queue before starting the tests.
        """
        logger.info("Setting up test environment...")
        self.user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "email@example.com",
            "username": "Czeslaw",
            'password':'testD.pass123'
        }

        logger.debug("Creating a test user...")
        self.user = User.objects.create_user(**self.user_data)

        logger.debug("Creating an OAuth2 application for the test user...")
        self.application = Application.objects.create(
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_id='testclientid',
            client_secret='testclientsecret'
        )

        self.url = reverse('login') 
        self.client_secret='testclientsecret'
        
        logger.debug("Clearing log queue before tests...")
        LogManager.clear_queue()
        logger.info("Test environment setup complete.")
    
    def tearDown(self):
        """
        Clean up after each test by resetting user permissions and clearing the log queue.
        """
        logger.info("Tearing down test environment...")
        User.clear_allowed_users()
        LogManager.clear_queue()
        logger.info("Test environment teardown complete.")
        super().tearDown()
        
    def bypass_ssl_verify_code_middleware(self, request, override_response=None):
        """
        Mock behavior for SSLMiddleware to bypass SSL checks during testing.
        """
        logger.debug("Bypassing SSL middleware for testing...")
        if override_response:
            logger.debug("Returning override response for SSL middleware.")
            return override_response
        
        request.username = "Czeslaw"
        request.email = "email@example.com"
        
        return self.get_response(request)
    
    def mock_dispatch(self, request, *args, **kwargs):
    
        return super(LoginAPIView, self).dispatch(request, *args, **kwargs)
        
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_verify_code_middleware)
    def test_login_with_valid_verification_code(self,mock_get_secret):
        """
        Test login with a valid verification code.
        Expect successful authentication with status 200 and 'access_token' in the response.
        """
        logger.info("Starting test: test_login_with_valid_verification_code")
        
        mock_get_secret.return_value = 'testclientsecret'

        secret_key = TwoFactor.generate_secret_key(self.user_data["email"],self.user_data["username"])
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now() 

        # Add the X-Verification-Code header for 2FA
        self.client.credentials(HTTP_X_VERIFICATION_CODE=verification_code)
        
        data = {
            'username': self.user_data["username"],
            'password': self.user_data["password"]
        }

        logger.debug("Sending POST request to login endpoint with username...")
        response = self.client.post(self.url, data)
        
        logger.debug(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        logger.debug("Validating response contains 'access_token'...")
        self.assertIn('access_token', response.json())
        
        logger.info("Test passed: test_login_with_valid_verification_code")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_verify_code_middleware)
    def test_login_with_no_valid_verification_code(self,mock_get_secret):
        """
        Test login with an invalid or expired verification code.
        Expect authentication failure with status 403 and appropriate error message.
        """
        logger.info("Starting test: test_login_with_no_valid_verification_code")
        
        mock_get_secret.return_value = 'testclientsecret'

        # Generate a TOTP using mismatched or incorrect data to simulate an invalid code
        logger.debug("Generating an invalid TOTP for 2FA...")
        secret_key = TwoFactor.generate_secret_key("example@come","Ryszard")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now() 

        # Add the X-Verification-Code header for 2FA
        self.client.credentials(HTTP_X_VERIFICATION_CODE=verification_code)
        
        data = {
            'username': self.user_data["username"],
            'password': self.user_data["password"]
        }

        logger.debug("Sending POST request to login endpoint with username...")
        response = self.client.post(self.url, data)
        
        logger.debug(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.json()["error"],"Invalid or expired code")
        logger.info("Test passed: test_login_with_no_valid_verification_code")

        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_successful_by_username(self,mock_get_secret):
        """
        Test successful login using the username and correct credentials.
        """
        logger.info("Starting test: test_login_successful_by_username")

        mock_get_secret.return_value = 'testclientsecret'

        data = {
            'username': self.user_data["username"],
            'password': self.user_data["password"]
        }

        logger.debug("Sending POST request to login endpoint with username...")
        response = self.client.post(self.url, data)
        
        logger.debug(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        logger.debug("Validating response contains 'access_token'...")
        self.assertIn('access_token', response.json())

        logger.debug("Checking if get_decrypted_secret was called correctly...")
        mock_get_secret.assert_called_once_with(self.user_data["username"], self.application.client_secret)
        
        logger.info("Test passed: test_login_successful_by_username")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_successful_by_email(self,mock_get_secret):
        """
        Test successful login using the email and correct credentials.
        """
        logger.info("Starting test: test_login_successful_by_email")

        mock_get_secret.return_value = 'testclientsecret'

        data = {
            'username': self.user_data["email"],
            'password': self.user_data["password"]
        }

        logger.debug("Sending POST request to login endpoint with email...")
        response = self.client.post(self.url, data)

        logger.debug(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        logger.debug("Validating response contains 'access_token'...")
        self.assertIn('access_token', response.json())
        
        logger.debug("Checking if get_decrypted_secret was called correctly...")
        mock_get_secret.assert_called_once_with(self.user_data["username"], self.application.client_secret)
        
        logger.info("Test passed: test_login_successful_by_email")
  
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(
        SSLMiddleware,
        '__call__',
        new=lambda self, request: bypass_ssl_middleware(
            self,
            request,
            JsonResponse(
                {'error': 'Only HTTPS connections are allowed.'}, 
                status=status.HTTP_403_FORBIDDEN),
        ),
    )
    def test_login_sll_is_not_secure(self,mock_get_secret):
        """
        Test login attempt when SSL is not secure.
        """
        logger.info("Starting test: test_login_ssl_is_not_secure")

        mock_get_secret.return_value = 'testclientsecret'

        data = {
            'username': self.user_data["email"],
            'password': self.user_data["password"]
        }

        logger.debug("Sending POST request to login endpoint without HTTPS...")
        response = self.client.post(self.url, data)

        logger.debug(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.json()["error"],"Only HTTPS connections are allowed.")
        
        logger.info("Test passed: test_login_ssl_is_not_secure")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(
        SSLMiddleware,
        '__call__',
        new=lambda self, request: bypass_ssl_middleware(
            self,
            request,
            JsonResponse(
                {'error': 'not a valid certificate.'}, 
                status=status.HTTP_401_UNAUTHORIZED),
        ),
    )
    def test_login_sll_no_client_cn(self,mock_get_secret):
        """
        Test login attempt with an invalid client certificate.
        """
        logger.info("Starting test: test_login_ssl_no_client_cn")

        mock_get_secret.return_value = 'testclientsecret'

        data = {
            'username': self.user_data["email"],
            'password': self.user_data["password"]
        }

        logger.debug("Sending POST request to login endpoint with invalid certificate...")
        response = self.client.post(self.url, data)

        logger.debug(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()["error"],'not a valid certificate.')
        
        logger.info("Test passed: test_login_ssl_no_client_cn")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(
        SSLMiddleware,
        '__call__',
        new=lambda self, request: bypass_ssl_middleware(
            self,
            request,
            JsonResponse(
                {'error': 'not a valid path'}, 
                status=status.HTTP_404_NOT_FOUND),
        ),
    )
    def test_login_sll_no_valid_path(self,mock_get_secret):
        """
        Test login attempt to a non-existent path.
        """
        logger.info("Starting test: test_login_ssl_no_valid_path")

        mock_get_secret.return_value = 'testclientsecret'

        data = {
            'username': self.user_data["email"],
            'password': self.user_data["password"]
        }

        logger.debug("Sending POST request to a non-existent login endpoint...")
        response = self.client.post(self.url, data)

        logger.debug(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()["error"],'not a valid path')
        
        logger.info("Test passed: test_login_ssl_no_valid_path")
   
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_incorrect_data(self,mock_get_secret):
        """
        Test login attempt with incorrect or unexpected input data.
        """
        logger.info("Starting test: test_login_incorrect_data")
        mock_get_secret.return_value = 'testclientsecret'
        
        data = {
            'username': self.user_data["email"],
            'password': self.user_data["password"],
            'someData': 'someData'
        }
        
        logger.debug("Sending POST request to login endpoint with incorrect data...")
        response = self.client.post(self.url, data)

        logger.debug(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()['error'], 'Incorrect data')
        
        logger.info("Test passed: test_login_incorrect_data")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_user_not_found(self,mock_get_secret):
        """
        Test case to ensure that a login attempt fails when no associated application is found for the user.
        """
        logger.info("Starting test: test_login_user_not_found")
        mock_get_secret.return_value = 'testclientsecret'
        
        error = 'Application for user not found'
        
        user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "rysiek@example.com",
            "username": 'Rysiek',
            'password':'Tes!@#$%^&*()_+<>?|.,~`092=-/[]'
        }
        
        logger.debug("Creating user with username: %s", user_data["username"])
        user = User.objects.create_user(**user_data)
        
        data = {
            'username': user_data["username"],
            'password': user_data["password"]
        }
        
        logger.debug("Sending POST request to login URL with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug("Received response: %s", response.json())
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()['error'], error)
        logger.info("Test passed: test_login_user_not_found")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_user_specjal_marks(self,mock_get_secret):
        """
        Test case to ensure that a user with a username containing special characters can log in successfully.
        """
        logger.info("Starting test: test_login_user_special_marks")
        mock_get_secret.return_value = 'testclientsecret'
        
        user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "rysiek@example.com",
            "username": 'Rysiek.12-+',
            'password':'Tes!@#$%^&*()_+<>?|.,~`092=-/[]'
        }

        logger.debug("Creating user with username: %s", user_data["username"])
        user = User.objects.create_user(**user_data)
    
        logger.debug("Creating application for user: %s", user.username)
        application = Application.objects.create(
            user=user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_id='newtestclientid',
            client_secret='testclientsecret'
        )

        data = {
            'username': user_data["username"],
            'password': user_data["password"]
        }
        
        logger.debug("Sending POST request to login URL with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug("Received response: %s", response.json())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        logger.info("Test passed: test_login_user_special_marks")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_user_long_password(self,mock_get_secret):
        """
        Test case to ensure that a user with an extremely long password can log in successfully.
        """
        logger.info("Starting test: test_login_user_long_password")
        mock_get_secret.return_value = 'testclientsecret'
        
        user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "rysiek@example.com",
            "username": 'Rysiek.12-+',
            'password':'Tes!@#$%^&*()_+<>?|.,~`092=-/[]'* 50
        }

        logger.debug("Creating user with username: %s", user_data["username"])
        user = User.objects.create_user(**user_data)
    
        logger.debug("Creating application for user: %s", user.username)
        application = Application.objects.create(
            user=user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_id='newtestclientid',
            client_secret='testclientsecret'
        )

        data = {
            'username': user_data["username"],
            'password': user_data["password"]
        }
        
        logger.debug("Sending POST request to login URL with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug("Received response: %s", response.json())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        logger.info("Test passed: test_login_user_long_password")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_aplication_grant_authorization_code(self,mock_get_secret):
        """
        Ensure a user can log in successfully with correct credentials.
        """
        logger.info("Starting test: test_login_aplication_grant_authorization_code")
        
        error='unauthorized_client'
        
        mock_get_secret.return_value = 'testclientsecret'

        user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "rysiek@example.com",
            "username": 'Rysiek.12-+',
            'password':'Tes!@#$%^&*()_+<>?|.,~`092=-/[]'* 50
        }

        logger.debug("Creating user with username: %s", user_data["username"])
        user = User.objects.create_user(**user_data)
    
        logger.debug("Creating application for user: %s", user.username)
        application = Application.objects.create(
            user=user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_id='newtestclientid',
            client_secret='testclientsecret'
        )

        data = {
            'username': user_data["username"],
            'password': user_data["password"]
        }
        
        logger.debug("Sending POST request to login URL with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug("Received response: %s", response.json())
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()['error'], error)
        
        logger.info("Test passed: test_login_aplication_grant_authorization_code")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_aplication_grant_implicity(self,mock_get_secret):
        """
        Test login with an application using the 'implicit' grant type.
        Expected result: The login attempt should fail with an 'unauthorized_client' error.
        """
        logger.info("Starting test: test_login_aplication_grant_implicity")
        error='unauthorized_client'
        
        mock_get_secret.return_value = 'testclientsecret'

        user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "rysiek@example.com",
            "username": 'Rysiek.12-+',
            'password':'Tes!@#$%^&*()_+<>?|.,~`092=-/[]'* 50
        }

        logger.debug("Creating user with data: %s", user_data)
        user = User.objects.create_user(**user_data)
        
        logger.debug("Creating application with 'implicit' grant type")
        application = Application.objects.create(
            user=user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_IMPLICIT,
            client_id='newtestclientid',
            client_secret='testclientsecret'
        )

        data = {
            'username': user_data["username"],
            'password': user_data["password"]
        }
        
        logger.debug("Sending login request with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug("Response status: %d, Response body: %s", response.status_code, response.json())
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()['error'], error)
        
        logger.info("Test passed: test_login_aplication_grant_implicity")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_inactive_user(self,mock_get_secret):
        """
        Test login with an inactive user account.
        Expected result: The login attempt should fail.
        """
        logger.info("Starting test: test_login_inactive_user")
        mock_get_secret.return_value = 'testclientsecret'

        user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "rysiek@example.com",
            "username": 'Rysiek.12-+',
            'password':'Tes!@#$%^&*()_+<>?|.,~`092=-/[]'* 50
        }

        logger.debug("Creating inactive user with data: %s", user_data)
        user = User.objects.create_user(**user_data)
        user.is_active = False
        user.save()
        
        application = Application.objects.create(
            user=user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_id='newtestclientid',
            client_secret='testclientsecret'
        )
        
        data = {
            'username': user_data["username"],
            'password': user_data["password"]
        }
        
        logger.debug("Sending login request with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug("Response status: %d, Response body: %s", response.status_code, response.json())
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        logger.info("Test passed: test_login_inactive_user")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_user_empty_string(self,mock_get_secret):
        """
        Test login with an empty username.
        Expected result: The login attempt should fail.
        """
        logger.info("Starting test: test_login_user_empty_string")
        mock_get_secret.return_value = 'testclientsecret'

        password = 'Tes!@#$%^&*()_+<>?|.,  ~`092=-/[]' * 50
        username = ''

        data = {
            'username': username,
            'password': password
        }
        
        logger.debug("Sending login request with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug("Response status: %d, Response body: %s", response.status_code, response.json())
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        logger.info("Test passed: test_login_user_empty_string")
        
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_password_empty_string(self,mock_get_secret):
        """
        Test login with an empty password.
        Expected result: The login attempt should fail.
        """
        logger.info("Starting test: test_login_password_empty_string")
        mock_get_secret.return_value = 'testclientsecret'

        password = ''
        username = 'Tes!@#$%^&*()_+<>?|.,  ~`092=-/[]'

        data = {
            'username': username,
            'password': password
        }
        
        logger.debug("Sending login request with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug("Response status: %d, Response body: %s", response.status_code, response.json())
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        logger.info("Test passed: test_login_password_empty_string")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_user_password_none(self,mock_get_secret):
        """
        Test login with both username and password as None.
        Expected result: A TypeError should be raised.
        """
        logger.info("Starting test: test_login_user_password_none")

        mock_get_secret.return_value = 'testclientsecret'

        password = None
        username = None

        data = {
            'username': username,
            'password': password
        }
        logger.debug("Sending login request with data: %s", data)
        with self.assertRaises(TypeError):
            response = self.client.post(self.url, data)
            
        logger.info("Test passed: test_login_user_password_none")

    def test_login_not_unique_client_id(self):
        """
        Test that creating an application with a non-unique client_id raises an IntegrityError.
        """
        logger.info("Starting test: test_login_not_unique_client_id")

        user_data = {
                "first_name": "testuser",
                "last_name": "Czwarty",
                "email": "rysiek@example.com",
                "username": 'Rysiek.12-+',
                'password':'Tes!@#$%^&*()_+<>?|.,~`092=-/[]'
        }

        user = User.objects.create_user(**user_data)
        with self.assertRaises(IntegrityError):
            application = Application.objects.create(
                user=user,
                client_type=Application.CLIENT_CONFIDENTIAL,
                authorization_grant_type=Application.GRANT_PASSWORD,
                client_id='testclientid',
                client_secret='testclientsecret'
            )
            
        logger.info("Test passed: test_login_not_unique_client_id")

    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_server_error_secret_key(self,mock_get_secret):
        """
        Test login behavior when an internal server error occurs while retrieving the secret key.
        """
        logger.info("Starting test: test_server_error_secret_key")
        
        error = "Failed to retrieve secret: 500 - Internal Server Error"
        mock_get_secret.return_value = mock_get_secret.side_effect = Exception(error)
        
        data = {
            'username': self.user_data['username'],
            'password': self.user_data['password']
        }
        
        logger.debug("Sending login request with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug(f"Response data: {response.json()}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], error)
        
        logger.info("Test passed: test_server_error_secret_key")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_decryption_timeout(self, mock_post):
        """
        Ensure the login fails if decryption of the client secret takes too long.
        """
        
        logger.info("Starting test: test_decryption_timeout")
        
        mock_post.side_effect = SecretServerError(Response(
                {'error': 'time expired to confirm try again'},
                status=status.HTTP_408_REQUEST_TIMEOUT
            ))

        data = {
            'username': self.user_data['username'],
            'password': self.user_data['password']
        }
        
        logger.debug("Sending login request with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug(f"Response data: {response.json()}")
        self.assertEqual(response.status_code, status.HTTP_408_REQUEST_TIMEOUT)
        self.assertEqual(response.json()["error"], 'time expired to confirm try again')
        
        logger.info("Test passed: test_decryption_timeout")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_decryption_invalid_credentials(self, mock_post):
        """
        Test login failure when the decryption of the client secret fails due to invalid credentials.
        """
        
        logger.info("Starting test: test_decryption_invalid_credentials")
        
        error = 'Error in retrieving secret for application client'
        
        mock_post.side_effect = SecretServerError(Response(
                {'error': error},
                status=status.HTTP_401_UNAUTHORIZED
        ))

        data = {
            'username': self.user_data['username'],
            'password': self.user_data['password']
        }
        
        logger.debug("Sending login request with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug(f"Response data: {response.json()}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()["error"], 'Error in retrieving secret for application client')
        
        logger.info("Test passed: test_decryption_invalid_credentials")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_sql_injection_attempt_does_not_alter_database(self, mock_get_secret):
        """
        Test that an SQL injection attempt in the login payload does not alter the database.
        """
        logger.info("Starting test: test_login_sql_injection_attempt_does_not_alter_database")
        
        mock_get_secret.return_value = 'testclientsecret'
        
        initial_user_count = User.objects.count()
        
        injection_payload = "'; DROP TABLE auth_user; --"
        data = {
            'username': injection_payload,
            'password': 'wrongpassword'
        }
        
        logger.debug("Sending login request with data: %s", data)
        response = self.client.post(self.url, data)
        
        logger.debug(f"Response data: {response.json()}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        post_injection_user_count = User.objects.count()
        logger.debug(f"User count after injection attempt: {post_injection_user_count}")
        
        self.assertEqual(initial_user_count, post_injection_user_count, "User count changed after SQL injection attempt")
        self.assertTrue(User.objects.filter(username=self.user_data["username"]).exists(), "Original user missing after SQL injection attempt")

        logger.info("Test passed: test_login_sql_injection_attempt_does_not_alter_database")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_invalid_credentials(self,mock_get_secret):
        """
        Ensure invalid credentials result in an error.
        """
        logger.info("Starting test: test_login_invalid_credentials")
        
        mock_get_secret.return_value = 'testclientsecret'
        
        data = {
            'username': 'invaliduser',
            'password': 'wrongpassword'
        }
        
        logger.debug(f"Attempting login with data: {data}")
        response = self.client.post(self.url, data)

        logger.debug(f"Response status: {response.status_code}, Response body: {response.json()}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json()['error'], 'Invalid credentials')
        
        logger.info("Test passed: test_login_invalid_credentials")

    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_too_many_attempts(self,mock_get_secret):
        """
        Ensure too many failed login attempts result in a lockout.
        """
        
        logger.info("Starting test: test_login_too_many_attempts")
        mock_get_secret.return_value = 'testclientsecret'
        
        data = {
            'username': self.user_data["username"],
            'password': 'wrongpassword'
        }
        
        logger.debug(f"Attempting login with incorrect password for user: {self.user_data['username']}")
        for _ in range(3):
            self.client.post(self.url, data)
        
        # Fourth attempt should result in lockout
        response = self.client.post(self.url, data)
        logger.debug(f"Lockout attempt response status: {response.status_code}, body: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(response.json()['error'], 'Too many login attempts. Try again later.')
        
        logger.info("Test passed: test_login_too_many_attempts")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_timeout_cache(self,mock_get_secret):
        """
        Ensure cache timeout works as expected, allowing login after the cooldown period.
        """

        logger.info("Starting test: test_login_timeout_cache")

        settings.CACHE_TIMEOUT = 2
        mock_get_secret.return_value = 'testclientsecret'
        
        data = {
            'username': self.user_data['username'],
            'password': 'wrongpassword'
        }
        
        logger.debug(f"Attempting login with incorrect password for user: {self.user_data['username']}")
        for _ in range(3):
            self.client.post(self.url, data)
        
        # Fourth attempt should result in lockout
        response = self.client.post(self.url, data)
        logger.debug(f"Lockout attempt response status: {response.status_code}, body: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(response.json()['error'], 'Too many login attempts. Try again later.')
        
        data['password'] = self.user_data['password']
        time.sleep(3)
        response = self.client.post(self.url, data)
        
        logger.debug(f"Login attempt after cooldown response status: {response.status_code}, body: {response.json()}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        logger.info("Test passed: test_login_timeout_cache")
        

    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_existing_token(self,mock_get_secret):
        """
        Ensure an error is returned if a user already has an active token.
        """

        logger.info("Starting test: test_login_existing_token")
        mock_get_secret.return_value = 'testclientsecret'
        
        # Create an active access token for the user
        token = AccessToken.objects.create(
            user=self.user,
            token=str(uuid.uuid4()),
            application=self.application,
            expires=timezone.now() + timezone.timedelta(hours=1)
        )
        
        refresh_token =  RefreshToken.objects.create(
            user=self.user,
            token=str(uuid.uuid4()),
            access_token=token,
            application=self.application,
        )
        
        data = {
            'username': self.user_data['username'],
            'password': self.user_data['password'],
        }
        
        logger.debug(f"Attempting login with existing active token for user: {self.user_data['username']}")
        response = self.client.post(self.url, data)
        
        logger.debug(f"Login response status: {response.status_code}, response body: {response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertNotEqual(token.token,response.json()['access_token'])
        
        logger.info("Test passed: test_login_existing_token")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_revoked_token(self,mock_get_secret):
        """
        Ensure that a revoked token is handled correctly, and a new token is issued upon login.
        """
        # Log the start of the test
        logger.info("Starting test for revoked token.")
        mock_get_secret.return_value = 'testclientsecret'
        
        token = AccessToken.objects.create(
            user=self.user,
            token=str(uuid.uuid4()),
            application=self.application,
            expires=timezone.now() + timezone.timedelta(hours=1)
        )

        # Revoke the token
        token.revoke()

        data = {
            'username': self.user_data['username'],
            'password': self.user_data['password'],
        }
        response = self.client.post(self.url, data)

        # Assert the expected response
        logger.info(f"Revoked token test response: {response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertNotEqual(token.token,response.json()['access_token'])
        
        logger.info("Test passed: test_revoked_token")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_multiple_token(self,mock_get_secret):
        """
        Ensure an error is returned if a user attempts to create more than one active token.
        """
        # Log the start of the test
        logger.info("Starting test for multiple tokens.")
        
        mock_get_secret.return_value = 'testclientsecret'
        
        token1 = AccessToken.objects.create(
            user=self.user,
            token=str(uuid.uuid4()),
            application=self.application,
            expires=timezone.now() + timezone.timedelta(hours=1)
        )
        
        with self.assertRaises(ValueError):
            token2 = AccessToken.objects.create(
                user=self.user,
                token=str(uuid.uuid4()),
                application=self.application,
                expires=timezone.now() + timezone.timedelta(hours=1)
            )

        data = {
            'username': self.user_data['username'],
            'password': self.user_data['password'],
        }
        response = self.client.post(self.url, data)

        # Assert the expected response
        logger.info("Multiple token test response:", response.data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        logger.info("Test passed: test_multiple_token")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_login_expired_token(self,mock_get_secret):
        """
        Ensure that expired tokens are handled correctly and a new token is issued upon login.
        """
        # Log the start of the test
        logger.info("Starting test for expired token.")
        
        mock_get_secret.return_value = 'testclientsecret'
        
        # Create an active access token for the user
        token = AccessToken.objects.create(
            user=self.user,
            token=str(uuid.uuid4()),
            application=self.application,
            expires=timezone.now() - timezone.timedelta(hours=1)
        )
        
        refresh_token =  RefreshToken.objects.create(
            user=self.user,
            token=str(uuid.uuid4()),
            access_token=token,
            application=self.application,
        )

        data = {
            'username': self.user_data['username'],
            'password': self.user_data['password'],
        }
        response = self.client.post(self.url, data)

        logger.info(f"Expired token test response: {response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertNotEqual(token.token,response.json()['access_token'])
        
        logger.info("Test passed: test_login_expired_token")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_concurrent_logins_same_user(self, mock_get_secret):
        """
        Ensure that multiple logins for the same user return either the same or a new token, as intended.
        """
        # Log the start of the test
        logger.info("Starting test for concurrent logins of the same user.")
        mock_get_secret.return_value = 'testclientsecret'
        
        AccessToken.objects.filter(user=self.user).delete()
        logger.info(f"list of acceccTokens:  {list(AccessToken.objects.filter(user=self.user).values_list('token', flat=True))}" )
        
        client1 = Client()

        data = {
            'username': self.user_data['username'],
            'password': self.user_data['password'],
        }
        
        response1 = client1.post(self.url, data)
        
        logger.info(f" client1 response: {response1.data}")
        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        
        current_session_key_client1 = client1.session.session_key
        self.assertIsNotNone(current_session_key_client1)
        
        session_exists = Session.objects.filter(session_key=current_session_key_client1).exists()
        self.assertTrue(session_exists)

        client2 = Client()

        response2 = client2.post(self.url, data)
        
        logger.info(f" client2 response: {response1.data}")
        current_session_key_client2 = client2.session.session_key
        
        session_exists = Session.objects.filter(session_key=current_session_key_client2).exists()
        self.assertTrue(session_exists)
        
        other_sessions = Session.objects.filter(session_data__contains=self.user.pk).exclude(session_key=current_session_key_client2)
        self.assertFalse(other_sessions.exists())

        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response1.json()['access_token'],response2.json()['access_token'])

        self.assertEqual(len(list(AccessToken.objects.filter(user=self.user).values_list('token', flat=True))),1)
        
        logger.info("Test passed: test_concurrent_logins_same_user")
 
    @patch('userauth.views.requests.Session.post') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch) 
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_invalid_credentials_with_mocked_post(self, mock_post):
        """
        Test case for handling invalid credentials with a mocked POST request.
        The test simulates the failure to retrieve the secret using invalid credentials.
        """
        logger.info("Test initiated for invalid credentials with mocked POST request.")
        
        data = {
            'username': self.user_data['username'],
            'password': self.user_data['password'],
        }
        
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 401
        mock_response.json.return_value = {"error": "Invalid credentials"}
        mock_response.text = f"Invalid credentials error details password: {data["password"]}" 
        mock_post.return_value = mock_response
        
        logger.debug(f"Mocked POST response set with status code {mock_response.status_code} and error message.")

        with self.assertLogs('django', level='DEBUG') as cm:
            logger.debug(f"Sending POST request with username: {data['username']} and password: {data['password']}")
            response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 401)
        logger.info("Received 401 Unauthorized response as expected.")
        
        self.assertEqual(response.json()['error'], 'Failed to retrieve secret: 401 - Invalid credentials error details password: testD.pass123')
        logger.info("Error message verified in response.")
        
        log_output = '\n'.join(cm.output)
        self.assertNotIn(data["password"], log_output)
        logger.info("Password not included in the log output, ensuring security compliance.")

        mock_post.assert_called_once()
        
        logger.info("Test passed: test_invalid_credentials_with_mocked_post")

@override_settings(SECURE_SSL_REDIRECT=False)  
class LogoutAPIViewTests(APITestCase):
    
    def setUp(self):
        """
        Set up test user, application for OAuth2 tokens, and URL for logout.
        This prepares everything required for the logout test cases.
        """
        logger.info("Setting up test user and OAuth2 application for logout tests.")
        self.user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "email@example.com",
            "username": "Czeslaw",
            'password':'testD.pass123'
        }

        self.user = User.objects.create_user(**self.user_data)
        logger.debug(f"Created test user: {self.user_data['username']}")
        
        self.user_data = {
            'username': self.user_data["username"],
            'password':  self.user_data["password"],
        }

        # Create an application for OAuth2 tokens
        self.application = Application.objects.create(
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_id='testclientid',
            client_secret='testclientsecret'
        )
        logger.debug(f"Created OAuth2 application for user {self.user.username}.")
        
        # Set the URL for the logout endpoint
        self.url = reverse("logout") 
        self.url_login = reverse('login') 
        
        logger.debug(f"Logout URL: {self.url}, Login URL: {self.url_login}")
        
        LogManager.clear_queue()
        
    def tearDown(self):
        """
        Clean up after each test, clearing allowed users and log queue.
        """
        logger.info("Tearing down after test execution.")
        User.clear_allowed_users()
        LogManager.clear_queue()
        super().tearDown()
        
    def mock_dispatch(self, request, *args, **kwargs):
    
        return super(LoginAPIView, self).dispatch(request, *args, **kwargs)
    
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    def logout_request(self, token,mock_get_secret):
        """
        Helper function to send a logout request with a specific token.
        """
        logger.info(f"Sending logout request with token: {token}")
        mock_get_secret.return_value = 'testclientsecret'
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        response = self.client.post(self.url)
        logger.debug(f"Logout response status: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_successful_logout_and_token_revocation(self,mock_get_secret):
        """
        Test case for successful logout and revocation of tokens.
        Ensures session is cleared, and access/refresh tokens are deleted.
        """
        logger.info("Test initiated: Successful logout and token revocation.")

        mock_get_secret.return_value = 'testclientsecret'

        response = self.client.post(
            self.url_login,
            data=json.dumps(self.user_data),
            content_type="application/json"
        )
        
        logger.debug(f"Login response status: {response.status_code} - Access token received.")

        self.assertTrue('_auth_user_id' in self.client.session)
        
        token = response.json()['access_token']
        logger.debug(f"Access token for the user: {token}")
                         
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        response = self.client.post(self.url)

        logger.debug(f"Logout response status: {response.status_code}, message: {response.data['message']}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.assertEqual(response.data["message"], "Successfully logged out")
        logger.info("Successfully logged out and token revoked.")
        
        self.assertFalse('_auth_user_id' in self.client.session)
        logger.debug("User session cleared after logout.")

        # Check that the access token is no longer in the database
        self.assertFalse(AccessToken.objects.filter(token="testaccesstoken").exists())
        # Check that the refresh token is no longer in the database
        self.assertFalse(RefreshToken.objects.filter(token="testrefreshtoken").exists())
        
        logger.info("Test passed: test_successful_logout_and_token_revocation")

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_logout_without_access_token(self):
        """
        Test case where the access token does not exist in the request.
        Should result in 400 error due to missing token.
        """
        logger.info("Test initiated: Logout without access token.")
        self.client.credentials() 
        response = self.client.post(self.url)
        logger.debug(f"Logout response status: {response.status_code} - Missing token.")
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'].code, "not_authenticated")
        
        logger.info("Test passed: test_logout_without_access_token")

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_logout_with_invalid_access_token(self):
        """
        Test case for logout with an invalid access token (token does not exist in DB).
        Ensures fallback logout behavior and orphaned refresh tokens are deleted.
        """
        logger.info("Starting test: test_logout_with_invalid_access_token")
        token = secrets.token_urlsafe(32)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        response = self.client.post(self.url)
        
        logger.info(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'].code, "not_authenticated")
        
        logger.info("Test passed: test_logout_with_invalid_access_token")

        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    @patch('oauth2_provider.models.Application.objects.get')
    def test_exception_during_logout(self, mock_application_get, mock_get_secret):
        """
        Test case for handling exceptions during token revocation.
        Simulates a scenario where an error occurs, ensuring proper handling and fallback logout.
        """
        logger.info("Starting test: test_exception_during_logout")
        
        mock_get_secret.return_value = 'testclientsecret'
        mock_application_get.return_value = self.application
        logger.debug(f"Mock application secret: {mock_get_secret.return_value}")
        
        response = self.client.post(self.url_login, self.user_data)
        token = response.json()['access_token']
        logger.debug(f"Obtained access token: {token}")
        logger.info(f"Response status code: {response.status_code}")
        
        self.assertTrue(AccessToken.objects.filter(token=token).exists())
        self.assertTrue(RefreshToken.objects.filter(access_token=AccessToken.objects.filter(token=token).first()).exists())
                         
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        logger.info("Simulating exception by deleting application...")
        mock_application_get.side_effect = Application.DoesNotExist 

        response = self.client.post(self.url)
        
        logger.info(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Application for user not found")
        
        logger.info("Test passed: test_exception_during_logout")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_logout_unauthenticated_user_access(self, mock_get_secret):
        """
        Test case for logout with an unauthenticated user.
        Ensures fallback logout behavior and cleanup of tokens and session.
        """
        logger.info("Starting test: test_logout_unauthenticated_user_access")
        mock_get_secret.return_value = 'testclientsecret'
        
        token = AccessToken.objects.create(
            user=self.user,
            token="testaccesstoken",
            application=self.application,
            expires=timezone.now() + timezone.timedelta(days=1),
            scope="read write"
        )
        
        logger.debug(f"Created token: {token.token}")
        
        session = self.client.session
        session.flush()
        session.save()
        
        logger.info("Flushed and saved session to simulate unauthenticated access.")
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        response = self.client.post(self.url)
        
        logger.info(f"Response status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Successfully logged out")
        
        self.assertFalse('_auth_user_id' in self.client.session)

        self.assertFalse(AccessToken.objects.filter(token="testaccesstoken").exists())
        self.assertFalse(RefreshToken.objects.filter(token="testrefreshtoken").exists())
        
        logger.info("Test passed: test_logout_unauthenticated_user_access")
    
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)    
    def test_logout_delete_token(self):
        """
        Test case for logout with an invalid access token (token does not exist in DB).
        Ensures fallback logout behavior and orphaned refresh tokens are deleted.
        """
        logger.info("Starting test: test_logout_delete_token")
        
        # Create a valid access token for the user
        token = AccessToken.objects.create(
            user=self.user,
            token="testaccesstoken",
            application=self.application,
            expires=timezone.now() + timezone.timedelta(days=1),
            scope="read write"
        )
        
        # Delete the token to simulate an invalid access token scenario
        token.delete()
        logger.info(f"Token has been deleted")

        # Set the Authorization header with the (now invalid) token
        self.client.credentials(HTTP_AUTHORIZATION="Bearer testaccesstoken")

        # Call the logout view with the invalid token
        response = self.client.post(self.url)
        logger.info(f"Response status code: {response.status_code}")

        # Assert the response status and error message for unauthenticated access
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'].code, "not_authenticated")
        
        logger.info("Test passed: test_logout_delete_token")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)    
    def test_logout_decrypted_secret(self,mock_decrypt_secret):
        """
        test case verifies no connection to secret server
        """
        logger.info("Starting test: test_logout_decrypted_secret")
        
        mock_decrypt_secret.side_effect = SecretServerError(response=Response({"error": "Secret retrieval failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR))
        token = AccessToken.objects.create(
            user=self.user,
            token="testaccesstoken",
            application=self.application,
            expires=timezone.now() + timezone.timedelta(days=1),
            scope="read write"
        )
        logger.debug(f"Access token created: {token.token}")

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        response = self.client.post(self.url)
        
        logger.info(f"Response received with status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        self.assertEqual(response.data["error"], "Secret retrieval failed")
        
        logger.info("Test passed: test_logout_decrypted_secret")
        
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_logout_expired_token(self):
        """
        Test case for logout with an expired access token.
        Ensures tokens are cleaned up properly.
        """
        logger.info("Starting test: test_logout_expired_token")

        token = AccessToken.objects.create(
            user=self.user,
            token="testaccesstoken",
            application=self.application,
            expires=timezone.now() - timezone.timedelta(days=1),
            scope="read write"
        )
        logger.debug(f"Expired token created: {token.token}")
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        response = self.client.post(self.url)
        
        logger.info(f"Response received with status code: {response.status_code}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        self.assertEqual(response.data['detail'].code, "not_authenticated")
        
        self.assertFalse('_auth_user_id' in self.client.session)
        
        delete_expired_tokens()
        logger.debug("Expired tokens deleted.")

        # Check that the access token is no longer in the database
        self.assertFalse(AccessToken.objects.filter(token="testaccesstoken").exists())
        
        logger.info("Test passed: test_logout_expired_token")
        
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_logout_invalid_format(self):
        """
        Test case for logout with an improperly formatted access token.
        """
        logger.info("Starting test: test_logout_invalid_format")

        token = AccessToken.objects.create(
            user=self.user,
            token="testaccesstoken",
            application=self.application,
            expires=timezone.now() + timezone.timedelta(days=1),
            scope="read write"
        )
        logger.debug(f"Valid token created: {token.token}")
        
        self.client.credentials(HTTP_AUTHORIZATION=f"{token}")
        response = self.client.post(self.url)
        logger.info(f"Response received with status code: {response.status_code}")
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'].code, "not_authenticated")
        
        logger.info("Test passed: test_logout_invalid_format")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_delete_application_during_logout(self,mock_get_secret):
        """
        Test case for logout when the associated application is deleted mid-process.
        """
        logger.info("Starting test: test_delete_aplication_during_logout")
        
        user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "email125@example.com",
            "username": "Czeslaw46",
            'password':'testD.pass123'
        }
        
        data = {
            'username': user_data['username'],
            'password': user_data['password'],
        }

        user = User.objects.create_user(**user_data)
        logger.debug(f"User created: {user.username}")

        # Create an application for OAuth2 tokens
        application = Application.objects.create(
            user=user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_id='testclientid254',
            client_secret='testclientsecret'
        )
        logger.debug(f"Application created: {application.client_id}")
        
        mock_get_secret.return_value = 'testclientsecret'
        client = APIClient()

        response = client.post(self.url_login, data)
        
        current_session_key = client.session.session_key
        logger.debug(f"Session key: {current_session_key}")
        
        token = response.json()['access_token']
        logger.info(f"Access token received: {token}")
        
        session_exists = Session.objects.filter(session_key=current_session_key).exists()
   
        self.assertTrue(AccessToken.objects.filter(token=token).exists())
        self.assertTrue(RefreshToken.objects.filter(access_token=AccessToken.objects.filter(token=token).first()).exists())
                         
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        # Modify the view temporarily to raise an exception by deleting the application
        application.delete()  
        logger.warning("Application deleted mid-process.")

        session_exists = Session.objects.filter(session_key=current_session_key).exists()
        
        logger.info(f"session exists:  {session_exists}")
        response = client.post(self.url)
        logger.info(f"Response received with status code: {response.status_code}")

        logger.info(f'Session key: {client.session.session_key}')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        self.assertEqual(response.data['detail'].code, "not_authenticated")

        # Verify orphaned refresh token cleanup in the case of an exception
        self.assertFalse(RefreshToken.objects.filter(access_token=AccessToken.objects.filter(token=token).first()).exists())
        self.assertFalse(AccessToken.objects.filter(token=token).exists())
        
        self.assertFalse('_auth_user_id' in self.client.session)
        
        logger.info("Test passed: test_delete_application_during_logout")
        
@override_settings(SECURE_SSL_REDIRECT=False)      
class TestCustomRefreshTokenView(APITestCase):
    def setUp(self):
        """
        Setup test user, OAuth application, access token, and refresh token
        to be used in the test cases.
        """
        self.user = User.objects.create_user(
            username="testuser",
            password="testD.pass123",
            first_name="testuser",
            last_name="Czwarty",
            email="email125@example.com",
        )
        
        # Create an OAuth application
        self.application = Application.objects.create(
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_id="testclientid",
            client_secret="testclientsecret",
        )
        
        self.token = AccessToken.objects.create(
            user=self.user,
            token="testaccesstoken",
            application=self.application,
            expires=timezone.now() + timezone.timedelta(days=1),
            scope="read write"
        )
        
        # Create a valid refresh token
        self.refresh_token = RefreshToken.objects.create(
            user=self.user,
            token="valid_refresh_token",
            application=self.application,
            access_token = self.token,
        )
        
        self.client = APIClient()
        self.url = reverse('refresh') 
        
        logger.info("Test setup completed. Test user, OAuth application, access token, and refresh token created.")

    def mock_dispatch(self, request, *args, **kwargs):
    
        return super(LoginAPIView, self).dispatch(request, *args, **kwargs)
    
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_successful_token_refresh(self, mock_decrypt_secret):
        """
        Test case for successfully refreshing a token using a valid refresh token.
        This ensures the API returns the new access token and other token details.
        """
        logger.debug("Starting test_successful_token_refresh with a valid refresh token.")
        mock_decrypt_secret.return_value = "testclientsecret"

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        
        logger.debug(f"Using refresh token: {self.refresh_token.token}")
                     
        response = self.client.post(self.url, {
            "refresh_token": self.refresh_token.token
            }
        )
        
        logger.debug(f"Response received: {response.json()}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access_token", response.json())
        self.assertIn("expires_in", response.json())
        self.assertIn("token_type", response.json())
        self.assertIn("scope", response.json())
        self.assertIn("refresh_token", response.json())
        
        logger.info("Test passed: Successfully refreshed the token and validated response.")

    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_missing_refresh_token(self, mock_decrypt_secret):
        """
        Test case for missing refresh token. This checks if the API returns
        the appropriate error message when no refresh token is provided.
        """
        logger.debug("Starting test_missing_refresh_token with missing refresh token")
        
        mock_decrypt_secret.return_value = "testclientsecret"
        
        response = self.client.post(self.url, {})
        
        logger.debug(f"Post refresh response: {response.json()}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'].code, "not_authenticated")
        
        logger.info("Test passed: Missing refresh token handled correctly.")

    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_invalid_refresh_token(self, mock_decrypt_secret):
        """
        Test case for invalid refresh token. It ensures that the API returns
        an error when an invalid refresh token is used.
        """
        logger.debug("Starting test_invalid_refresh_token with invalid refresh token")
        
        mock_decrypt_secret.return_value = "testclientsecret"
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        response = self.client.post(self.url, {
            "refresh_token": "invalid_refresh_token"
        })
        logger.debug(f"Response for invalid refresh token: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["error"], "Invalid refresh token")
        
        logger.info("Test passed: Invalid refresh token handled correctly.")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_invalid_refresh_token_empty_string(self, mock_decrypt_secret):
        """
        Test case for an empty string refresh token. It checks if the API returns
        an error when an empty refresh token is provided.
        """
        logger.debug("Starting test_invalid_refresh_token_empty_string with empty refresh token")
        
        mock_decrypt_secret.return_value = "testclientsecret"
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        response = self.client.post(self.url, {
            "refresh_token": ""
        })
        
        logger.debug(f"Response for empty refresh token: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["error"], "Missing credentials")
        
        logger.info("Test passed: Empty refresh token handled correctly.")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret')
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch) 
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_invalid_refresh_token_double(self, mock_decrypt_secret):
        """
        Test case to ensure that the API properly handles duplicate refresh tokens
        and removes them from the system.
        """
        logger.debug("Starting test_invalid_refresh_token_double with duplicate refresh token")
        
        mock_decrypt_secret.return_value = "testclientsecret"
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            token="valid_refresh_token",
            application=self.application,
        )
        
        response = self.client.post(self.url, {
            "refresh_token": refresh_token.token
        })
        logger.debug(f"Response for duplicate refresh token: {response.json()}")
        
        self.assertEqual(0,RefreshToken.objects.filter(token=refresh_token.token).count())
        self.assertEqual(0,AccessToken.objects.filter(token=self.token.token).count())
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["error"], "Duplicate refresh tokens found and removed.")
        
        logger.info("Test passed: Duplicate refresh tokens handled correctly.")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_invalid_refresh_token_no_access_token(self, mock_decrypt_secret):
        """
        Test case for when no access token is associated with the refresh token.
        The API should return an error indicating the refresh token has expired.
        """
        logger.debug("Starting test_invalid_refresh_token_no_access_token with no access token")
        
        mock_decrypt_secret.return_value = "testclientsecret"
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            token="valid_refresh_token_2",
            application=self.application,
        )
        
        response = self.client.post(self.url, {
            "refresh_token": refresh_token.token
        })
        logger.debug(f"Response for refresh token without access token: {response.json()}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["error"], "Refresh token has expired")
        
        logger.info("Test passed: Refresh token without access token handled correctly.")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_invalid_refresh_token_expired_access_token(self, mock_decrypt_secret):
        """
        Test case for expired access token with a valid refresh token. It ensures
        that the system rejects the refresh token if the associated access token has expired.
        """
        logger.debug("Starting test_invalid_refresh_token_expired_access_token")
        
        mock_decrypt_secret.return_value = "testclientsecret"
        
        user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "rysiek@example.com",
            "username": 'Rysiek',
            'password':'Tes!@#$%^&*()_+<>?|.,~`092=-/[]'
        }
        

        user = User.objects.create_user(**user_data)
        
        application = Application.objects.create(
            user=user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_id='testclientid254',
            client_secret='testclientsecret'
        )
        
        token = AccessToken.objects.create(
            user=user,
            token="testaccesstoken_2",
            application=application,
            expires=timezone.now() - timezone.timedelta(days=1),
            scope="read write"
        )
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        refresh_token = RefreshToken.objects.create(
            user=user,
            token="valid_refresh_token_2",
            application=self.application,
            access_token = token,
        )
        
        response = self.client.post(self.url, {
            "refresh_token": refresh_token.token
        })
        logger.debug(f"Response for expired access token: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        logger.info("Test passed: Expired access token correctly rejected with refresh token.")

    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_secret_server_error(self, mock_decrypt_secret):
        """
        Test case to simulate a server error during secret retrieval. It ensures that
        the system handles server-side failures correctly.
        """
        logger.debug("Starting test_secret_server_error with simulated server error")
        
        mock_decrypt_secret.side_effect = SecretServerError(response=Response({"error": "Secret retrieval failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR))

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        response = self.client.post(self.url, {
            "refresh_token": self.refresh_token.token
        })
        logger.debug(f"Response for server error: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data["error"], "Secret retrieval failed")
        
        logger.info("Test passed: Secret server error handled correctly.")

    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_unexpected_error(self, mock_decrypt_secret):
        """
        Test case for an unexpected error. The system should catch and log
        the error without exposing sensitive information.
        """
        logger.debug("Starting test_unexpected_error with unexpected error")
        
        mock_decrypt_secret.side_effect = Exception("Unexpected error")

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        response = self.client.post(self.url, {
            "refresh_token": self.refresh_token.token
        })
        logger.debug(f"Response for unexpected error: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["error"], "Unexpected error")
        
        logger.info("Test passed: Unexpected error handled correctly.")
     
@override_settings(SECURE_SSL_REDIRECT=False)      
class QRCodeViewTest(APITestCase):

    def setUp(self):
        """Set up initial data for tests."""
        self.user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "email@example.com",
            "username": "Czeslaw",
            'password':'testD.pass123'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.signer = TimestampSigner(salt=settings.SERVER_SALT)
        self.valid_token = self.signer.sign(self.user.id)
        self.invalid_token = "invalid_token_format"
        self.used_token = self.signer.sign(self.user.id)
        self.expired_token = self.signer.sign(self.user.id)

        logger.debug("Clearing log queue before tests...")
        LogManager.clear_queue()
        self.clear_token()
        logger.info("Test environment setup complete.")
        
    def tearDown(self):
        """
        Clean up after each test .
        """
        logger.info("Tearing down test environment...")
        User.clear_allowed_users()
        LogManager.clear_queue()
        logger.info("Test environment teardown complete.")
        super().tearDown()
    
    def clear_token(self):
        token = UsedToken.objects.filter(token=self.valid_token).first() 
        if token:
            token.delete()
            logger.info(f"Token has been removed")
            

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_valid_token(self):
        """Test access with a valid token."""
        url = reverse('qrcode', kwargs={'token': self.valid_token})
        logger.info(f"Testing valid token with URL: {url}")

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('image', response.data)
        logger.info("Valid token test passed. QR code generated successfully.")

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_already_used_token(self):
        """Test access with a token that has already been used."""
        url = reverse('qrcode', kwargs={'token': self.used_token})
        logger.info(f"Testing already used token with URL: {url}")
        UsedToken.objects.create(token=self.used_token, user=self.user)
        self.assertTrue(UsedToken.objects.filter(token=self.used_token).exists())

        response = self.client.get(url, HTTP_ACCEPT="text/html")
        logger.debug(f"Received response: {response.status_code} {response.context['error']}")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('This link has already been used.', response.context['error'])
        logger.info("Already used token test passed.")

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_invalid_token_format(self):
        """Test access with a token that has an invalid format."""
        url = reverse('qrcode', kwargs={'token': self.invalid_token})
        logger.info(f"Testing invalid token format with URL: {url}")

        response = self.client.get(url, HTTP_ACCEPT="text/html")
        logger.debug(f"Received response: {response.status_code} {response.context['error']}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid token format', response.context['error'])
        logger.info("Invalid token format test passed.")

    @override_settings(TOKEN_TIMEOUT=2)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_expired_token(self):
        """Test access with an expired token."""

        url = reverse('qrcode', kwargs={'token': self.valid_token})
        logger.info(f"Testing expired token with URL: {url}")
        time.sleep(4)
        response = self.client.get(url, HTTP_ACCEPT="text/html")
        logger.debug(f"Received response: {response.status_code} {response.content}")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('Link has expired', response.context['error'])
        logger.info("Expired token test passed.")

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_nonexistent_user(self):
        """Test access with a token for a non-existent user."""
        token_for_nonexistent_user = self.signer.sign(99999)  
        url = reverse('qrcode', kwargs={'token': token_for_nonexistent_user})
        logger.info(f"Testing token for a non-existent user with URL: {url}")

        response = self.client.get(url, HTTP_ACCEPT="text/html")
        logger.debug(f"Received response: {response.status_code} {response.content}")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('User does not exist', response.context['error'])
        logger.info("Non-existent user token test passed.")
        
@override_settings(SECURE_SSL_REDIRECT=False)     
class SendQRLinkViewTests(APITestCase):
    """
    Test suite for the SendQRLinkView class.
    """

    def setUp(self):
        """
        Set up test data and API client.
        """
        self.user_data = {
            "first_name": "testuser",
            "last_name": "Czwarty",
            "email": "email@example.com",
            "username": "Czeslaw",
            'password':'testD.pass123'
        }
        self.admin_user = User.objects.create_superuser(**self.user_data)
        self.regular_user = User.objects.create_user(
            username="user",
            email="user@example.com",
            password=self.user_data['password'],
            first_name=self.user_data['first_name'],
            last_name=self.user_data['last_name']
        )
        self.url = lambda user_id: reverse('qrlink', kwargs={'user_id': user_id})

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_get_as_admin(self):
        """
        Ensure an admin can access the GET endpoint and send the QR code email.
        """
        self.client.force_authenticate(user=self.admin_user)
        
        with patch('userauth.views.SendQRLinkView.generate_secure_link', return_value="https://example.com/fake-link"):
            with patch('userauth.views.SendQRLinkView.send_email') as mock_send_email:
                response = self.client.get(self.url(self.regular_user.id), HTTP_ACCEPT="text/html")
                
        logger.debug(f"Received response: {response.status_code} {response.content}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('The link was sent', response.data['message'])
        mock_send_email.assert_called_once_with(self.regular_user, "https://example.com/fake-link")

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_get_as_non_admin(self):
        """
        Ensure non-admin users cannot access the endpoint.
        """
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(self.url(self.regular_user.id), HTTP_ACCEPT="text/html")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_invalid_user_id_format(self):
        """
        Ensure the view returns a 400 response for invalid user ID formats.
        """
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.url("invalid_id"), HTTP_ACCEPT="text/html")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid user ID', response.context['error'])

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_nonexistent_user(self):
        """
        Ensure the view returns a 404 response for a non-existent user ID.
        """
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.url(9999), HTTP_ACCEPT="text/html")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('User does not exist', response.context['error'])

    @patch.object(TimestampSigner, 'sign', side_effect=Exception("Token generation failed"))
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_secure_link_generation_failure(self, mock_sign):
        """
        Ensure the view handles errors during secure link generation.
        """
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.url(self.regular_user.id), HTTP_ACCEPT="text/html")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Token generation failed', response.context['error'])

    @patch('userauth.views.SendQRLinkView.send_email', side_effect=Exception("Email sending failed"))
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_email_sending_failure(self, mock_send_email):
        """
        Ensure the view handles errors during email sending.
        """
        self.client.force_authenticate(user=self.admin_user)
        
        with patch('userauth.views.SendQRLinkView.generate_secure_link', return_value="https://example.com/fake-link"):
            response = self.client.get(self.url(self.regular_user.id), HTTP_ACCEPT="text/html")
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('Email sending failed', response.context['error'])

    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)
    def test_http_method_not_allowed(self):
        """
        Ensure non-GET methods return a 405 response.
        """
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.post(self.url(self.regular_user.id), HTTP_ACCEPT="text/html")
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertIn('Invalid method', response.context['error'])

        

        


        
        
    
        
    
    
