import json
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from unittest import mock
from middleware.ssl_middleware import SSLMiddleware  
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND, HTTP_406_NOT_ACCEPTABLE
from oauth2_provider.models import AccessToken, Application
import uuid
from django.utils import timezone
import logging

logger = logging.getLogger("test_logger")

class SSLMiddlewareTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = SSLMiddleware(lambda request: request)
        self.User = get_user_model()
        
        self.user = self.User.objects.create_user(
            username='testuser', email='testuser@example.com', password='passsUda24.a3@!wor',
            first_name='testuser', last_name='testuserlastname'
        )
        
        self.application = Application.objects.create(
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_id='testclientid',
            client_secret='testclientsecret'
        )
        
        
        self.superuser = self.User.objects.create_superuser(
            username='admin', email='admin@example.com', password='adminpasssUda24.a3@!wor',
            first_name='admin', last_name='adminlastname'
        )
        
        logger.info("Test setup completed with user and superuser creation.")

    def test_https_required_insecure_request_text(self):
        """Test that insecure (non-HTTPS) requests are blocked if REQUIRE_HTTPS is true."""

        logger.info("Starting test: test_https_required_insecure_request_text")
        request = self.factory.post('/login', secure=False,HTTP_ACCEPT='text/html')
        with self.settings(SECURE_SSL_REDIRECT=True):
            response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        self.assertEqual(response['Content-Type'], 'text/html; charset=utf-8')
        self.assertIn('Only HTTPS connections are allowed.', response.content.decode())
        
        logger.info("Test passed: test_https_required_insecure_request_text")
        
    def test_https_required_insecure_request_json(self):
        """Test that insecure (non-HTTPS) requests are blocked if REQUIRE_HTTPS is true."""

        logger.info("Starting test: test_https_required_insecure_request_json")
        request = self.factory.post('/login', secure=False,HTTP_ACCEPT='application/json')  
        with self.settings(SECURE_SSL_REDIRECT=True):
            response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        self.assertEqual(response['Content-Type'], 'application/json')
        response_data = json.loads(response.content)
        self.assertIn('Only HTTPS connections are allowed.', response_data['error'])
        
        logger.info("Test passed: test_https_required_insecure_request_json")

    def test_missing_client_certificate_cn(self):
        """Test response when HTTPS request is missing client certificate CN."""
        logger.info("Starting test: test_missing_client_certificate_cn")
        request = self.factory.post("/login")
        request.is_secure = lambda: True
        response = self.middleware(request)
        response_data = json.loads(response.content)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response_data['error'], 'not a valid certificate.')
        
        logger.info("Test passed: test_missing_client_certificate_cn")

    @mock.patch("userauth.models.User.is_user_allowed", return_value=False)
    def test_user_not_allowed(self, mock_is_user_allowed):
        """Test response when a user is not allowed to log in."""
        logger.info("Starting test: test_user_not_allowed")
        
        request = self.factory.post("/login",HTTP_ACCEPT='text/html')
        request.is_secure = lambda: True
        request.META["HTTP_X_SSL_CLIENT_CN"] = "unauthorized_user"
        response = self.middleware(request)
        self.assertEqual(response.status_code, 401)
        self.assertIn('not a valid user', response.content.decode())
        
        logger.info("Test passed: test_user_not_allowed")
        
    def test_login_path_invalid_json(self):
        """Test the /login path with invalid JSON body."""
        logger.info("Starting test: test_login_path_invalid_json")
        
        request = self.factory.post('/login', secure=True, data="notjson",content_type="application/json" )
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.user.username
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'Invalid JSON')
        
        logger.info("Test passed: test_login_path_invalid_json")
        
    def test_login_path_invalid_format(self):
        """Test the /login path with an invalid format for text/html content."""
        logger.info("Starting test: test_login_path_invalid_forma")
        
        request = self.factory.post('/login', secure=True, data="notjson", HTTP_ACCEPT='text/html',content_type="text/html")
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.user.username
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        self.assertIn('Browser access not allowed', response.content.decode())
        
        logger.info("Test passed: test_login_path_invalid_forma")
        
    def test_login_path_username_mismatch(self):
        """Test the /login path with username mismatch."""
        logger.info("Starting test: test_login_path_username_mismatch")
        
        request = self.factory.post(
            '/login', secure=True, data=json.dumps({'username': self.superuser.username}), content_type="application/json"
        )
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.user.username
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'Incorrect user or certificate')
        
        logger.info("Test passed: test_login_path_username_mismatch")
        
    def test_login_path_username_empty(self):
        """Test the /login path with an empty username."""
        logger.info("Starting test: test_login_path_username_empty")
        
        request = self.factory.post(
            '/login', secure=True, data=json.dumps({'username': ''}), content_type="application/json"
        )
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.user.username
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'Username is required for login.')
        
        logger.info("Test passed: test_login_path_username_empty")
        
    def test_login_path_username_email(self):
        """Test the /login path when the username does not match the email in the SSL client certificate."""
        logger.info("Starting test: test_login_path_username_email")
        
        request = self.factory.post(
            '/login', secure=True, data=json.dumps({'username': 'cos@example.com'}), content_type="application/json"
        )
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.user.username
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'Incorrect user')
        
        logger.info("Test passed: test_login_path_username_email")
        
    def test_login_path_username_mismatch_wrong_user(self):
        """Test the /login path when the username mismatches with another user."""
        logger.info("Starting test: test_login_path_username_mismatch_wrong_user")
        
        request = self.factory.post(
            '/login', secure=True, data=json.dumps({'username': self.superuser.username}), content_type="application/json"
        )
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.user.username
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'Incorrect user or certificate')
        
        logger.info("Test passed: test_login_path_username_mismatch_wrong_user")
        
    def test_refresh_path_missing_token(self):
        """Test the /refresh path with no token provided in the request."""
        logger.info("Starting test: test_refresh_path_missing_token")
        
        request = self.factory.post('/refresh', secure=True, content_type='application/json',)
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.user.username

        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'No valid Access token')
        
        logger.info("Test passed: test_refresh_path_missing_token")
            
    def test_refresh_path_invalid_token(self):
        """Test the /refresh path with an invalid token."""
        logger.info("Starting test: test_refresh_path_invalid_token")
        
        request = self.factory.post('/refresh', secure=True, content_type='application/json',)
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.superuser.username
        token = AccessToken.objects.create(
            user=self.user,
            token=str(uuid.uuid4()),
            application=self.application,
            expires=timezone.now() + timezone.timedelta(hours=1)
        )

        request = self.factory.post(
                                '/refresh', 
                                secure=True,
                                content_type='application/json',
                                HTTP_AUTHORIZATION=f"Bearer {token.token}"
                                )
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.superuser.username
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'Incorrect user or certificate')
        
        logger.info("Test passed: test_refresh_path_invalid_token")
        
    def test_refresh_path_invalid_db_token(self):
        """Test the /refresh path with a token not present in the database."""
        logger.info("Starting test: test_refresh_path_invalid_db_token")
        token='dummy_token'
        request = self.factory.post(
                                '/refresh', 
                                secure=True,
                                content_type='application/json',
                                HTTP_AUTHORIZATION=f"Bearer {token}"
                                )
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.superuser.username

        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'No valid Access token')
        
        logger.info("Test passed: test_refresh_path_invalid_db_token")
        
    def test_refresh_path_invalid_token_empty_user(self):
        """Test the /refresh path with a token linked to an empty user."""
        logger.info("Starting test: test_refresh_path_invalid_token_empty_user")
        
        token = AccessToken.objects.create(
            token=str(uuid.uuid4()),
            application=self.application,
            expires=timezone.now() + timezone.timedelta(hours=1)
        )

        request = self.factory.post(
                                '/refresh', 
                                secure=True,
                                content_type='application/json',
                                HTTP_AUTHORIZATION=f"Bearer {token.token}"
                                )
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.superuser.username
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'No valid Access token')
        
        logger.info("Test passed: test_refresh_path_invalid_token_empty_user")

    def test_admin_with_invalid_certificate(self):
        """Test admin access with an invalid SSL_CLIENT_SAN_DNS_0 header."""
        logger.info("Starting test: test_admin_with_invalid_certificate")
        
        request = self.factory.get("/admin", secure=True, HTTP_ACCEPT='text/html')
        request.META["SSL_CLIENT_SAN_DNS_0"] = "not_admin"
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.user.username
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertIn(b'Certificate not appropriate', response.content)
        
        logger.info("Test passed: test_admin_with_invalid_certificate")
        
    def test_admin_with_no_superuser(self):
        """Test admin access with not superuser accsess"""
        logger.info("Starting test: test_admin_with_no_superuser")
        request = self.factory.get("/admin", secure=True, HTTP_ACCEPT='text/html')
        request.META["SSL_CLIENT_SAN_DNS_0"] = "admin"
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.user.username
        response = self.middleware(request)

        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertIn(b'User has no permissions', response.content)
        
        logger.info("Test pass: test_admin_with_no_superuser")
        
    def test_admin_path_valid_superuser(self):
        """Test the /admin path with a valid superuser certificate."""
        logger.info("Starting test: test_admin_path_valid_superuser")
        request = self.factory.get('/admin', secure=True, **{'HTTP_X_SSL_CLIENT_CN': self.superuser.username, 'SSL_CLIENT_SAN_DNS_0': 'admin'},HTTP_ACCEPT='text/html')
        response = self.middleware(request)
        self.assertEqual(response, request)
        
        logger.info("Test passed: test_admin_path_valid_superuser")
        
    def test_admin_path_valid_superuser_no_valid_accept(self):
        """Test the /admin path with a valid superuser certificate.and no valid accept"""
        logger.info("Starting test: test_admin_path_valid_superuser")
        request = self.factory.get('/admin', secure=True, **{'HTTP_X_SSL_CLIENT_CN': self.superuser.username, 'SSL_CLIENT_SAN_DNS_0': 'admin'})
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_406_NOT_ACCEPTABLE)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'No valid Request')
        
        logger.info("Test passed: test_admin_path_valid_superuser_no_valid_accept")

    def test_invalid_path(self):
        """Test an invalid path."""
        logger.info("Starting test: test_invalid_path")
        
        request = self.factory.get('/invalid', secure=True, content_type='application/json')
        request.META['HTTP_X_SSL_CLIENT_CN'] = self.user.username
        response = self.middleware(request)
        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['error'], 'not a valid path')
        
        logger.info("Test passed: test_invalid_path")
