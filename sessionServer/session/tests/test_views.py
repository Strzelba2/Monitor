from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch
from oauth2_provider.models import AccessToken, RefreshToken, Application
from django.urls import reverse
from django.utils import timezone
from django.test import override_settings
from userauth.models import User
from session.models import Server, Session, TemporaryToken
from session.managers import LogManager
from session.serializers import ServerSerializer,ServerAvailabilitySerializer
from userauth.views import LoginAPIView
from middleware.ssl_middleware import SSLMiddleware
from userauth.tests.test_views import bypass_ssl_middleware
import base64
import hmac
import hashlib
import json
import logging

logger = logging.getLogger(__name__)


@override_settings(SECURE_SSL_REDIRECT=False)  
class ServerAvailableAPIViewTest(APITestCase):
    def setUp(self):
        
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
        
        self.login_data = {
            'username': self.user_data["username"],
            'password':  self.user_data["password"],
        }
        
        location = ["Europe","Asia","North America","Poland","Africa"]
        for i in range(5):
            port = 8080 + i
            Server.objects.create(
                name=f'Server {i}',
                ip_address=f"127.0.{i}.1",
                port=port,
                location=location[i],
                user=self.user,
                trusty=True,
                available=True
            )
        
        self.url = reverse('availableServers') 
        self.url_login = reverse('login') 
        
    def tearDown(self):
        """
        Clean up after each test by resetting user permissions and clearing the log queue.
        """
        logger.info("Tearing down test environment...")
        User.clear_allowed_users()
        LogManager.clear_queue()
        logger.info("Test environment teardown complete.")
        super().tearDown()
    
    def mock_dispatch(self, request, *args, **kwargs):
    
        return super(LoginAPIView, self).dispatch(request, *args, **kwargs)
    
    def login(self,mock_get_secret):
        mock_get_secret.return_value = 'testclientsecret'

        response = self.client.post(
            self.url_login,
            data=json.dumps(self.login_data),
            content_type="application/json"
        )
        
        logger.debug(f"Login response status: {response.status_code} - Access token received.")

        self.assertTrue('_auth_user_id' in self.client.session)
        
        token = response.json()['access_token']
        
        return token
      
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_successful_retrieval_of_available_servers(self,mock_get_secret):
        """Test that available servers are retrieved successfully."""
        logger.info("Starting test: test_successful_retrieval_of_available_servers")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.get(f"{self.url}?search=''")
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        expected_servers = Server.objects.filter(available=True)
        serializer = ServerSerializer(expected_servers, many=True)
        logger.info(f"{serializer.data}")
        self.assertEqual(response.json(), serializer.data)
        
        logger.info("Test Passed: test_successful_retrieval_of_available_servers")

    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)    
    def test_filtering_with_search_query_by_location(self,mock_get_secret):
        """Test filtering available servers using a search query."""
        logger.info("Starting test: test_filtering_with_search_query_by_location")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        response = self.client.get(f"{self.url}?search=Europe")
        
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_servers = Server.objects.filter(available=True, location__icontains="Europe")
        serializer = ServerSerializer(expected_servers, many=True)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.json(), serializer.data)
        
        logger.info("Test Passed: test_filtering_with_search_query_by_location")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)    
    def test_filtering_with_search_query_by_name(self,mock_get_secret):
        """Test filtering available servers using a search query."""
        logger.info("Starting test: test_filtering_with_search_query_by_name")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        response = self.client.get(f"{self.url}?search=Server 1")
        
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_servers = Server.objects.filter(available=True, location__icontains="Asia")
        serializer = ServerSerializer(expected_servers, many=True)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.json(), serializer.data)
        
        logger.info("Test Passed: test_filtering_with_search_query_by_name")
    
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)     
    def test_throttling_behavior(self,mock_get_secret):
        """Test throttling is applied."""
        logger.info("Starting test: test_throttling_behavior")
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        for _ in range(10): 
            self.client.get(self.url)

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        logger.info("Test Passed: test_throttling_behavior") 
    
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)     
    def test_server_error_handling(self,mock_get_secret):
        """Test that the view handles server errors gracefully."""
        logger.info("Starting test: test_server_error_handling")
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.get(f"{self.url}?searched=Server 1")
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.json()) 
        
        logger.info("Test Passed: test_server_error_handling")  
    
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)     
    def test_requires_authentication(self):
        logger.info("Starting test: test_requires_authentication")
        """Test that authentication is required."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        logger.info("Test Passed: test_requires_authentication")
        
@override_settings(SECURE_SSL_REDIRECT=False)  
class GenerateSessionViewTests(APITestCase):
    def setUp(self):
        
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
        
        self.login_data = {
            'username': self.user_data["username"],
            'password':  self.user_data["password"],
        }

        self.server = Server.objects.create(
                name=f'Server 1',
                ip_address=f"127.0.0.1",
                port=8080,
                location="Poland",
                trusty=True,
                available=True
            )
        
        self.url = reverse('session') 
        self.url_login = reverse('login') 
    
    def tearDown(self):
        """
        Clean up after each test by resetting user permissions and clearing the log queue.
        """
        logger.info("Tearing down test environment...")
        User.clear_allowed_users()
        LogManager.clear_queue()
        logger.info("Test environment teardown complete.")
        super().tearDown()
    
    def mock_dispatch(self, request, *args, **kwargs):
    
        return super(LoginAPIView, self).dispatch(request, *args, **kwargs)
    
    def login(self,mock_get_secret):
        mock_get_secret.return_value = 'testclientsecret'

        response = self.client.post(
            self.url_login,
            data=json.dumps(self.login_data),
            content_type="application/json"
        )
        
        logger.debug(f"Login response status: {response.status_code} - Access token received.")

        self.assertTrue('_auth_user_id' in self.client.session)
        
        token = response.json()['access_token']
        
        return token
      
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_generate_session_success(self,mock_get_secret):
        """Test session creation with valid data."""
        logger.info("Starting test: test_generate_session_success")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        self.assertIn('expires', response.json())
        
        logger.info("Test Passed: test_generate_session_success")
     
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_generate_session_invalid_data(self,mock_get_secret):
        """Test session creation with invalid data."""
        logger.info("Starting test: test_generate_session_invalid_data")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={})
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('server_name', response.json())
        
        logger.info("Test Passed: test_generate_session_invalid_data")
      
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_generate_session_server_not_found(self,mock_get_secret):
        """Test session creation when the server does not exist."""
        logger.info("Starting test: test_generate_session_server_not_found")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': 999})
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()['error'], 'Server with name 999 not found')
        
        logger.info("Test Passed: test_generate_session_server_not_found")
    
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)     
    def test_generate_session_server_unavailable(self,mock_get_secret):
        """Test session creation when the server is not available."""
        logger.info("Starting test: test_generate_session_server_unavailable")
        
        self.server.user = self.user
        self.server.save()
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.json()['error'], f'Server with name {self.server.name} is not available')
        
        logger.info("Test Passed: test_generate_session_server_unavailable")
      
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_generate_session_existing_active_session(self,mock_get_secret):
        """Test returning an existing active session."""
        logger.info("Starting test: test_generate_session_existing_active_session")
        session = Session.objects.create(user=self.user, server=self.server)
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()['sessionId'], session.sessionId)
        
        logger.info("Test Passed: test_generate_session_existing_active_session")
        
@override_settings(SECURE_SSL_REDIRECT=False)         
class UpdateServerAvailabilityViewTests(APITestCase):
    def setUp(self):
        self.server = Server.objects.create(
                name=f'Server 1',
                ip_address=f"127.0.0.1",
                port=8080,
                location="Poland",
                trusty=True,
                available=False
            )
        self.url = reverse('updateServer', kwargs={'server_name': self.server.name})
        
    def tearDown(self):
        """
        Clean up after each test by resetting user permissions and clearing the log queue.
        """
        logger.info("Tearing down test environment...")
        User.clear_allowed_users()
        LogManager.clear_queue()
        logger.info("Test environment teardown complete.")
        super().tearDown()
        
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware) 
    def test_update_server_availability_success(self):
        """Test updating server availability with valid data."""
        logger.info("Starting test: test_update_server_availability_success")
        
        response = self.client.patch(self.url, data={'available': True, 'screens':2}, format='json')
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()['message'], 'Server availability updated successfully')
        self.server.refresh_from_db()
        self.assertTrue(self.server.available)
        
        logger.info("Test Passed: test_update_server_availability_success")
     
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_update_server_availability_missing_field(self):
        """Test updating server availability with missing 'available' field."""
        logger.info("Starting test: test_update_server_availability_missing_field")
        
        response = self.client.patch(self.url, data={}, format='json')
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("The \"available\" field is required", response.json()['error'])
        
        logger.info("Test Passed: test_update_server_availability_missing_field")
     
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)    
    def test_update_server_availability_invalid_type(self):
        """Test updating server availability with invalid 'available' field type."""
        logger.info("Starting test: test_update_server_availability_invalid_type")
        
        response = self.client.patch(self.url, data={'available': 'yes','screens':"cos"}, format='json')
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("The \"available\" field must be a boolean", response.json()['error'])
        
        logger.info("Test Passed: test_update_server_availability_invalid_type")
     
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_update_server_availability_server_not_found(self):
        """Test updating availability for a server that does not exist."""
        logger.info("Starting test: test_update_server_availability_server_not_found")
        
        invalid_url = reverse('updateServer', kwargs={'server_name': 'NonExistentServer'})
        response = self.client.patch(invalid_url, data={'available': True,'screens':2}, format='json')
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("Server 'NonExistentServer' not found.", response.json()['detail'])
        
        logger.info("Test Passed: test_update_server_availability_server_not_found")
        
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_update_server_availability_server_wrong_ip_address(self):
        """Test updating availability for a server with invalid address ip."""
        logger.info("Starting test: test_update_server_availability_server_wrong_ip_address")
        
        self.server.ip_address = "78.0.0.9"
        self.server.save()
        response = self.client.patch(self.url, data={'available': True,'screens':2}, format='json')
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('Your IP is not allowed.', response.json()['detail'])
        
        logger.info("Test Passed: test_update_server_availability_server_wrong_ip_address")
      
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_partial_update_server_availability(self):
        """Test that partial updates are handled correctly."""
        logger.info("Starting test: test_partial_update_server_availability")
        response = self.client.patch(self.url, data={'available': True,'screens':2 , 'extra_field': 'ignored'}, format='json')
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.server.refresh_from_db()
        self.assertTrue(self.server.available)
        # Ensure that no unexpected fields are added or updated
        self.assertFalse(hasattr(self.server, 'extra_field'))
        
        logger.info("Test Passed: test_partial_update_server_availability")
        
@override_settings(SECURE_SSL_REDIRECT=False)        
class GeneratetokenTests(APITestCase):
    def setUp(self):
        
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
        
        self.login_data = {
            'username': self.user_data["username"],
            'password':  self.user_data["password"],
        }
        self.path = "/Test/Request"

        self.server = Server.objects.create(
                name=f'Server 1',
                ip_address=f"127.0.0.1",
                port=8080,
                location="Poland",
                trusty=True,
                available=True
            )
        
        self.url = reverse('session') 
        self.url_send = reverse('send') 
        self.url_login = reverse('login') 
        
    def tearDown(self):
        """
        Clean up after each test by resetting user permissions and clearing the log queue.
        """
        logger.info("Tearing down test environment...")
        User.clear_allowed_users()
        LogManager.clear_queue()
        logger.info("Test environment teardown complete.")
        super().tearDown()
    
    def mock_dispatch(self, request, *args, **kwargs):
    
        return super(LoginAPIView, self).dispatch(request, *args, **kwargs)
    
    def login(self,mock_get_secret):
        mock_get_secret.return_value = 'testclientsecret'

        response = self.client.post(
            self.url_login,
            data=json.dumps(self.login_data),
            content_type="application/json"
        )
        
        logger.debug(f"Login response status: {response.status_code} - Access token received.")

        self.assertTrue('_auth_user_id' in self.client.session)
        
        token = response.json()['access_token']
        
        return token
      
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_generate_token_success(self,mock_get_secret):
        """Test hmac creation with valid data."""
        logger.info("Starting test: test_generate_token_success")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        session = Session.objects.filter(sessionId = response.json()["sessionId"]).first()
        
        logger.info(f"session: {session}")
        
        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"test_body_hash").decode(),
        }
        http_forwarded = "203.0.113.195"
        response = self.client.post(self.url_send, data ,HTTP_X_FORWARDED_FOR=http_forwarded)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.json())
        
        token = TemporaryToken.objects.filter(session = session).first()
        
        self.assertEqual(token.path, self.path)
        
        message = f"{session.sessionId}{self.server.ip_address}{http_forwarded}{data['method']}{token.created_at}{self.user.username}{data['encode_body']}"
        expected_hmac = hmac.new(token.token.encode(), message.encode(), hashlib.sha256).hexdigest()
        expected_encoded_hmac = base64.b64encode(expected_hmac.encode()).decode()

        self.assertEqual(response.data["token"], expected_encoded_hmac)
        
        logger.info("Test Passed: test_generate_token_success")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_generate_empty_encode_body(self,mock_get_secret):
        """Test hmac creation with empty body."""
        logger.info("Starting test: test_generate_empty_encode_body")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        session = Session.objects.filter(sessionId = response.json()["sessionId"]).first()
        
        logger.info(f"session: {session}")
        
        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"").decode(),
        }
        http_forwarded = "203.0.113.195"
        response = self.client.post(self.url_send, data ,HTTP_X_FORWARDED_FOR=http_forwarded)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.json())
        
        token = TemporaryToken.objects.filter(session = session).first()
        
        self.assertEqual(token.path, self.path)
        
        message = f"{session.sessionId}{self.server.ip_address}{http_forwarded}{data['method']}{token.created_at}{self.user.username}{data['encode_body']}"
        expected_hmac = hmac.new(token.token.encode(), message.encode(), hashlib.sha256).hexdigest()
        expected_encoded_hmac = base64.b64encode(expected_hmac.encode()).decode()

        self.assertEqual(response.data["token"], expected_encoded_hmac)
        
        logger.info("Test Passed: test_generate_empty_encode_body")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_generate_empty_encode_body(self,mock_get_secret):
        """Test hmac creation with empty body."""
        logger.info("Starting test: test_generate_empty_encode_body")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        session = Session.objects.filter(sessionId = response.json()["sessionId"]).first()
        
        logger.info(f"session: {session}")
        
        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"").decode(),
        }
        http_forwarded = "203.0.113.195"
        response = self.client.post(self.url_send, data ,HTTP_X_FORWARDED_FOR=http_forwarded)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.json())
        
        token = TemporaryToken.objects.filter(session = session).first()
        
        self.assertEqual(token.path, self.path)
        
        message = f"{session.sessionId}{self.server.ip_address}{http_forwarded}{data['method']}{token.created_at}{self.user.username}{data['encode_body']}"
        expected_hmac = hmac.new(token.token.encode(), message.encode(), hashlib.sha256).hexdigest()
        expected_encoded_hmac = base64.b64encode(expected_hmac.encode()).decode()

        self.assertEqual(response.data["token"], expected_encoded_hmac)
        
        logger.info("Test Passed: test_generate_empty_encode_body")
     
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)     
    def test_invalid_server_name(self,mock_get_secret):
        """Test hmac creation with invalid server name."""
        logger.info("Starting test: test_invalid_server_name")
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        session = Session.objects.filter(sessionId = response.json()["sessionId"]).first()
        
        logger.info(f"session: {session}")
        
        data = {
            "server_name": "invalid name",
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"test_body_hash").decode(),
        }
        
        response = self.client.post(self.url_send, data)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn("detail", response.json())
        
        logger.info("Test Passed: test_invalid_server_name")
     
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_invalid_session(self,mock_get_secret):
        """Test hmac creation with invalid session."""
        logger.info("Starting test: test_invalid_session")
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"test_body_hash").decode(),
        }

        response = self.client.post(self.url_send, data)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn("error", response.json())
        
        logger.info("Test Passed: test_invalid_session")
     
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)    
    def test_invalid_serializer_data(self,mock_get_secret):
        """Test hmac creation with invalid data."""
        logger.info("Starting test: test_invalid_serializer_data")
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        
        # Missing required fields
        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            # "encode_body" missing
        }

        response = self.client.post(self.url_send, data)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("encode_body", response.json())
        
        logger.info("Test Passed: test_invalid_serializer_data")
 
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)    
    def test_unauthorized_request(self):
        """Test hmac creation with unauthorized request."""
        logger.info("Starting test: test_unauthorized_request")

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer testToken")

        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"test_body_hash").decode(),
        }

        response = self.client.post(self.url_send, data)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("detail", response.json())
        
        logger.info("Test Passed: test_unauthorized_request")
 
@override_settings(SECURE_SSL_REDIRECT=False)        
class VerifySessionViewTests(APITestCase):
    def setUp(self):
        
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
        
        self.login_data = {
            'username': self.user_data["username"],
            'password':  self.user_data["password"],
        }
        self.path = "/Test/Request"

        self.server = Server.objects.create(
                name=f'Server 1',
                ip_address=f"127.0.0.1",
                port=8080,
                location="Poland",
                trusty=True,
                available=True
            )
        
        self.url = reverse('session') 
        self.url_send = reverse('send') 
        self.url_login = reverse('login') 
        self.url_verify = reverse('verifySession', kwargs={'server_name': self.server.name})
        
    def tearDown(self):
        """
        Clean up after each test by resetting user permissions and clearing the log queue.
        """
        logger.info("Tearing down test environment...")
        User.clear_allowed_users()
        LogManager.clear_queue()
        logger.info("Test environment teardown complete.")
        super().tearDown()

    def mock_dispatch(self, request, *args, **kwargs):
    
        return super(LoginAPIView, self).dispatch(request, *args, **kwargs)
    
    def login(self,mock_get_secret):
        mock_get_secret.return_value = 'testclientsecret'

        response = self.client.post(
            self.url_login,
            data=json.dumps(self.login_data),
            content_type="application/json"
        )
        
        logger.debug(f"Login response status: {response.status_code} - Access token received.")

        self.assertTrue('_auth_user_id' in self.client.session)
        
        token = response.json()['access_token']
        
        return token
      
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_valid_request(self,mock_get_secret):
        """Test verify session creation with valid data."""
        logger.info("Starting test: test_valid_request")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        session = Session.objects.filter(sessionId = response.json()["sessionId"]).first()
        
        logger.info(f"session: {session}")
        
        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"test_body_hash").decode(),
        }
        
        remote_address = "192.168.1.100"
        response = self.client.post(self.url_send, data, REMOTE_ADDR=remote_address)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.json())
        
        hmac = response.json()["token"]
        timestamp = str(int(timezone.now().timestamp()))
        
        logger.info(f"{session.created.timestamp()}/{timestamp}")
        
        verify_data = {
            'authorization': f"{session.sessionId}:{hmac}:{timestamp}",
            'path': self.path,
            'method': 'POST',
            'encode_body': base64.b64encode(b"test_body_hash").decode(),
            'host': remote_address
        }
        
        response = self.client.post(self.url_verify, verify_data)
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Validation ok')
        session.refresh_from_db()
        self.server.refresh_from_db()

        self.assertFalse(self.server.available)
        self.assertEqual(self.server.user, self.user)
        
        logger.info("Test Passed: test_valid_request")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_valid_request_many_times(self,mock_get_secret):
        """Test verify session creation many times request."""
        logger.info("Starting test: test_valid_request_many_times")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        session = Session.objects.filter(sessionId = response.json()["sessionId"]).first()
        
        logger.info(f"session: {session}")
        
        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"test_body_hash").decode(),
        }
        
        remote_address = "192.168.1.100"
        response = self.client.post(self.url_send, data, REMOTE_ADDR=remote_address)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.json())
        
        hmac = response.json()["token"]
        timestamp = str(int(timezone.now().timestamp()))
        
        logger.info(f"{session.created.timestamp()}/{timestamp}")
        
        verify_data = {
            'authorization': f"{session.sessionId}:{hmac}:{timestamp}",
            'path': self.path,
            'method': 'POST',
            'encode_body': base64.b64encode(b"test_body_hash").decode(),
            'host': remote_address
        }
        
        response = self.client.post(self.url_verify, verify_data)
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Validation ok')
        self.server.available = True
        self.server.user = None
        self.server.save()
        
        session.refresh_from_db()
        self.server.refresh_from_db()
        
        response = self.client.post(self.url_verify, verify_data)
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Validation ok')

        logger.info("Test Passed: test_valid_request_many_times")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_invalid_body(self,mock_get_secret):
        """Test verify session  creation with invalid body."""
        logger.info("Starting test: test_invalid_body")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        session = Session.objects.filter(sessionId = response.json()["sessionId"]).first()
        
        logger.info(f"session: {session}")
        
        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"test_body_hash").decode(),
        }
        
        remote_address = "192.168.1.100"
        response = self.client.post(self.url_send, data, REMOTE_ADDR=remote_address)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.json())
        
        hmac = response.json()["token"]
        timestamp = str(int(timezone.now().timestamp()))
        
        logger.info(f"{session.created.timestamp()}/{timestamp}")
        
        verify_data = {
            'authorization': f"{session.sessionId}:{hmac}:{timestamp}",
            'path': self.path,
            'method': 'POST',
            'encode_body': 'test_body',
            'host':'127.0.0.1'   
        }
        
        response = self.client.post(self.url_verify, verify_data)
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        logger.info("Test Passed: test_invalid_body")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_invalid_path(self,mock_get_secret):
        """Test verify session creation with invalid path."""
        logger.info("Starting test: test_invalid_path")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        session = Session.objects.filter(sessionId = response.json()["sessionId"]).first()
        
        logger.info(f"session: {session}")
        
        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"test_body_hash").decode(),
        }
        
        remote_address = "192.168.1.100"
        response = self.client.post(self.url_send, data, REMOTE_ADDR=remote_address)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.json())
        
        hmac = response.json()["token"]
        timestamp = str(int(timezone.now().timestamp()))
        
        logger.info(f"{session.created.timestamp()}/{timestamp}")
        
        verify_data = {
            'authorization': f"{session.sessionId}:{hmac}:{timestamp}",
            'path': '/test/path',
            'method': 'POST',
            'encode_body': base64.b64encode(b"test_body_hash").decode(),
            'host':'127.0.0.1'
        }
        
        response = self.client.post(self.url_verify, verify_data)
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        logger.info("Test Passed: test_invalid_path")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_invalid_session(self,mock_get_secret):
        """Test verify session creation with invalid session."""
        logger.info("Starting test: test_invalid_session")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")       
 
        timestamp = str(int(timezone.now().timestamp()))

        
        verify_data = {
            'authorization': f"someSessionId:{hmac}:{timestamp}",
            'path': '/test/path',
            'method': 'POST',
            'encode_body': base64.b64encode(b"test_body_hash").decode(),
            'host':'127.0.0.1'
        }
        
        response = self.client.post(self.url_verify, verify_data)
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        logger.info("Test Passed: test_invalid_session")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_invalid_authorization(self,mock_get_secret):
        """Test verify session creation with invalid authorization."""
        logger.info("Starting test: test_invalid_authorization")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")       
 
        timestamp = str(int(timezone.now().timestamp()))

        
        verify_data = {
            'authorization': f"someSessionId{hmac}{timestamp}",
            'path': '/test/path',
            'method': 'POST',
            'encode_body': base64.b64encode(b"test_body_hash").decode(),
        }
        
        response = self.client.post(self.url_verify, verify_data)
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        logger.info("Test Passed: test_invalid_authorization")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_invalid_method(self,mock_get_secret):
        """Test verify session creation with invalid method."""
        logger.info("Starting test: test_invalid_method")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        session = Session.objects.filter(sessionId = response.json()["sessionId"]).first()
        
        logger.info(f"session: {session}")
        
        data = {
            "server_name": self.server.name,
            "method": "POST",
            "path": self.path,
            "encode_body": base64.b64encode(b"test_body_hash").decode(),
        }
        
        remote_address = "192.168.1.100"
        response = self.client.post(self.url_send, data, REMOTE_ADDR=remote_address)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.json())
        
        hmac = response.json()["token"]
        timestamp = str(int(timezone.now().timestamp()))
        
        logger.info(f"{session.created.timestamp()}/{timestamp}")
        
        verify_data = {
            'authorization': f"{session.sessionId}:{hmac}:{timestamp}",
            'path': self.path,
            'method': 'GET',
            'encode_body': base64.b64encode(b"test_body_hash").decode(),
            'host':remote_address
        }
        
        response = self.client.post(self.url_verify, verify_data)
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        logger.info("Test Passed: test_invalid_method")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_invalid_host(self,mock_get_secret):
        """Test verify session creation with invalid hos."""
        logger.info("Starting test: test_invalid_host")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={'server_name': self.server.name})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sessionId', response.json())
        session = Session.objects.filter(sessionId = response.json()["sessionId"]).first()
        
        logger.info(f"session: {session}")
        
        data = {
            "server_name": self.server.name,
            "method": "GET",
            "path": self.path,
            "encode_body": base64.b64encode(b"test_body_hash").decode(),
        }
        
        remote_address = "192.168.1.100"
        response = self.client.post(self.url_send, data, REMOTE_ADDR=remote_address)
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.json())
        
        hmac = response.json()["token"]
        timestamp = str(int(timezone.now().timestamp()))
        
        logger.info(f"{session.created.timestamp()}/{timestamp}")
        
        verify_data = {
            'authorization': f"{session.sessionId}:{hmac}:{timestamp}",
            'path': self.path,
            'method': 'GET',
            'encode_body': base64.b64encode(b"test_body_hash").decode(),
            'host':'127.0.0.1'
        }
        
        response = self.client.post(self.url_verify, verify_data)
        logger.info(f"data: {response.json()}")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        logger.info("Test Passed: test_invalid_host")
        
        
@override_settings(SECURE_SSL_REDIRECT=False)  
class LogoutSessionViewTests(APITestCase):
    def setUp(self):
        
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
        
        self.login_data = {
            'username': self.user_data["username"],
            'password':  self.user_data["password"],
        }

        self.server = Server.objects.create(
                name=f'Server 1',
                ip_address=f"127.0.0.1",
                port=8080,
                location="Poland",
                trusty=True,
                available=True
            )
        
        self.url = reverse('session') 
        self.url_login = reverse('login') 
        self.url_logout = reverse('logoutSession')
        
    def tearDown(self):
        """
        Clean up after each test by resetting user permissions and clearing the log queue.
        """
        logger.info("Tearing down test environment...")
        User.clear_allowed_users()
        LogManager.clear_queue()
        logger.info("Test environment teardown complete.")
        super().tearDown()
    
    def mock_dispatch(self, request, *args, **kwargs):
    
        return super(LoginAPIView, self).dispatch(request, *args, **kwargs)
    
    def login(self,mock_get_secret):
        mock_get_secret.return_value = 'testclientsecret'

        response = self.client.post(
            self.url_login,
            data=json.dumps(self.login_data),
            content_type="application/json"
        )
        
        logger.debug(f"Login response status: {response.status_code} - Access token received.")

        self.assertTrue('_auth_user_id' in self.client.session)
        
        token = response.json()['access_token']
        
        return token
      
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_logout_session_successful(self,mock_get_secret):
        """Test session logout with valid data."""
        logger.info("Starting test: test_logout_session_successful")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={"server_name": self.server.name})
        
        logger.info(f"data: {response.json()}")
        session_id = response.json()["sessionId"]

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("sessionId", response.json())
        
        #simulate validation session
        self.server.user = self.user
        self.server.save()
        
        response = self.client.post(self.url_logout, {'session_id':session_id })
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Logout session sucessful')
        self.assertFalse(Session.objects.filter(sessionId=session_id).exists())
        self.server.refresh_from_db()
        self.assertTrue(self.server.available)
        self.assertIsNone(self.server.user)
        
        logger.info("Test Passed: test_logout_session_successful")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_invalid_session_id(self,mock_get_secret):
        """Test session logout with invalid session id."""
        logger.info("Starting test: test_invalid_session_id")
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url_logout, {'session_id': 'invalid_id'})
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()['error'], 'Session invalid_id do not exist')
        
        logger.info("Test Passed: test_invalid_session_id")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_user_mismatch(self,mock_get_secret):
        """Test session logout with invalid user."""
        logger.info("Starting test: test_user_mismatch")
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        user_data = {
            "first_name": "othertestuser",
            "last_name": "Other_Czwarty",
            "email": "other@example.com",
            "username": "Other",
            'password':'testD.pass123'
        }
        
        other_user = User.objects.create_user(**user_data)
        
        session = Session.objects.create(user=other_user, server=self.server)
        
        response = self.client.post(self.url_logout, {'session_id': session.sessionId})
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['error'], 'Invalid user for session')
        self.assertFalse(Session.objects.filter(sessionId=session.sessionId).exists())
        
        logger.info("Test Passed: test_user_mismatch")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_server_mismatch(self,mock_get_secret):
        """Test session logout with invalid server."""
        logger.info("Starting test: test_server_mismatch")
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        other_server = Server.objects.create(
                name=f'Server 2',
                ip_address=f"127.0.0.3",
                port=8081,
                location="Poland",
                trusty=True,
                available=True,
                user = self.user
            )
 
        session = Session.objects.create(user=self.user, server=self.server)
        
        response = self.client.post(self.url_logout, {'session_id': session.sessionId})

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.json()['error'], 'Server mismatch for session')
        self.assertFalse(Session.objects.filter(sessionId=session.sessionId).exists())
        self.assertFalse(Server.objects.filter(name=session.server.name).exists())
        self.assertFalse(Server.objects.filter(name=self.server.name).exists())
        
        logger.info("Test Passed: test_server_mismatch")
    
    
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)     
    def test_invalid_payload(self,mock_get_secret):
        """Test session logout with invalid data."""
        logger.info("Starting test: test_invalid_payload")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url_logout, {'invalid_field': 'value'})
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('session_id', response.data)
        
        logger.info("Test Passed: test_invalid_payload")
        
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_logout_session_server_for_user_not_exist(self,mock_get_secret):
        """Test session logout with wrong server"""
        logger.info("Starting test: test_logout_session_server_for_user_not_exist")
        
        token = self.login(mock_get_secret)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={"server_name": self.server.name})
        
        logger.info(f"data: {response.json()}")
        session_id = response.json()["sessionId"]

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("sessionId", response.json())
        
        response = self.client.post(self.url_logout, {'session_id':session_id })
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()['message'], 'Server is waiting for a connection')
        self.assertFalse(Session.objects.filter(sessionId=session_id).exists())
        self.assertTrue(Server.objects.filter(name=self.server.name).exists())
        
        logger.info("Test Passed: test_logout_session_server_for_user_not_exist")
        
        
@override_settings(SECURE_SSL_REDIRECT=False)  
class UpdateSessionViewTests(APITestCase):
    def setUp(self):
        
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
        
        self.login_data = {
            'username': self.user_data["username"],
            'password':  self.user_data["password"],
        }

        self.server = Server.objects.create(
                name=f'Server 1',
                ip_address=f"127.0.0.1",
                port=8080,
                location="Poland",
                trusty=True,
                available=True
            )
        
        self.url = reverse('session') 
        self.url_login = reverse('login') 
        self.url_update = reverse('updateSession')
        
    def tearDown(self):
        """
        Clean up after each test by resetting user permissions and clearing the log queue.
        """
        logger.info("Tearing down test environment...")
        User.clear_allowed_users()
        LogManager.clear_queue()
        logger.info("Test environment teardown complete.")
        super().tearDown()
    
    def mock_dispatch(self, request, *args, **kwargs):
    
        return super(LoginAPIView, self).dispatch(request, *args, **kwargs)
    
    def login(self,mock_get_secret):
        mock_get_secret.return_value = 'testclientsecret'

        response = self.client.post(
            self.url_login,
            data=json.dumps(self.login_data),
            content_type="application/json"
        )
        
        logger.debug(f"Login response status: {response.status_code} - Access token received.")

        self.assertTrue('_auth_user_id' in self.client.session)
        
        token = response.json()['access_token']
        
        return token
      
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_update_session_successful(self,mock_get_secret):
        """Test update session with valid data."""
        logger.info("Starting test: test_update_session_successful")
        
        token = self.login(mock_get_secret)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, data={"server_name": self.server.name})
        
        logger.info(f"data: {response.json()}")
        session_id = response.json()["sessionId"]

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("sessionId", response.json())
        
        #simulate validation session
        self.server.user = self.user
        self.server.save()
        
        response = self.client.post(self.url_update, {"session_id": session_id})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("sessionId", response.json())
        self.assertFalse(Session.objects.filter(sessionId="valid-session-id").exists())
        self.assertTrue(Session.objects.filter(user=self.user, server=self.server).exists())
        
        logger.info("Test Passed: test_update_session_successful")
 
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_invalid_session_id(self,mock_get_secret):
        """Test update session with invalid session id."""
        logger.info("Starting test: test_invalid_session_id")
        
        token = self.login(mock_get_secret)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url_update, {"session_id": "invalid-session-id"})

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("error", response.json())
        
        logger.info("Test Passed: test_invalid_session_id")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_update_session_invalid_server(self,mock_get_secret):
        """Test update session with invalid server."""
        logger.info("Starting test: test_update_session_invalid_server")
        
        token = self.login(mock_get_secret)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        other_server = Server.objects.create(
                name=f'Server 2',
                ip_address=f"127.0.0.3",
                port=8081,
                location="Poland",
                trusty=True,
                available=True,
                user = self.user
            )
 
        session = Session.objects.create(user=self.user, server=self.server)
        response = self.client.post(self.url_update, {"session_id": session.sessionId})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(Session.objects.filter(sessionId=session.sessionId).exists())
        self.assertIn("error", response.json())
        
        logger.info("Test Passed: test_update_session_invalid_server")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)  
    def test_update_session_invalid_server_without_user(self,mock_get_secret):
        """Test update session with invalid server without user."""
        logger.info("Starting test: test_update_session_invalid_server_without_user")
        token = self.login(mock_get_secret)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
 
        session = Session.objects.create(user=self.user, server=self.server)
        response = self.client.post(self.url_update, {"session_id": session.sessionId})
        
        logger.info(f"data: {response.json()}")
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(Session.objects.filter(sessionId=session.sessionId).exists())
        self.assertIn("error", response.json())
        
        logger.info("Test Passed: test_update_session_invalid_server_without_user")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)     
    def test_invalid_payload(self,mock_get_secret):
        """Test update session with invalid data."""
        logger.info("Starting test: test_invalid_payload")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url_update, {'invalid_field': 'value'})
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('session_id', response.data)
        
        logger.info("Test Passed: test_invalid_payload")
        
    @patch('userauth.views.LoginAPIView.get_decrypted_secret') 
    @patch('userauth.views.LoginAPIView.dispatch', new=mock_dispatch)
    @patch.object(SSLMiddleware, '__call__',  new=bypass_ssl_middleware)   
    def test_user_mismatch(self,mock_get_secret):
        """Test update session with invalid user."""
        logger.info("Starting test: test_user_mismatch")
        
        token = self.login(mock_get_secret)
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        user_data = {
            "first_name": "othertestuser",
            "last_name": "Other_Czwarty",
            "email": "other@example.com",
            "username": "Other",
            'password':'testD.pass123'
        }
        
        other_user = User.objects.create_user(**user_data)
        
        session = Session.objects.create(user=other_user, server=self.server)
        
        response = self.client.post(self.url_update, {'session_id': session.sessionId})
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['error'], 'Invalid user for session')
        self.assertFalse(Session.objects.filter(sessionId=session.sessionId).exists())
        
        logger.info("Test Passed: test_user_mismatch")
