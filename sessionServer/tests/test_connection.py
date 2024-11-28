import pytest
import requests
from requests.exceptions import SSLError
import conftest
import constants
import ssl
import time
import pyotp
from userauth.two_factor import TwoFactor

from concurrent.futures import ThreadPoolExecutor, as_completed

import logging

logger = logging.getLogger(__name__)


@pytest.mark.usefixtures("docker_services", "secret_provider")
class TestSessionServer:
    """Test suite for the Session Server's functionality."""
    
    def send_request(self, session, url, username, password, headers):
        """Helper method to send login requests."""
        logger.debug(f"Sending request to {url} with username: {username}")
        
        
        response = session.post(
            url,
            json={"username": username, "password": password},
            cert=(constants.CERT_FILE, constants.KEY_FILE),
            headers=headers,
            verify=constants.CA_FILE
        )
        logger.debug(f"Received response: {response.status_code} {response.content}")
        return response
    
    def test_secret_provider_functionality(self, secret_provider):
        """Test if the secret provider is initialized and functional."""
        logger.debug("Testing secret provider setup.")
        assert secret_provider is not None, "Secret provider is not initialized!"
        logger.debug("Secret provider is set up and ready for testing.")
        
    def test_login_http(self):
        """Test login endpoint over HTTP. Ensure access is forbidden."""
        logger.debug("Testing HTTP login for forbidden access.")
        try:
            response = requests.post(constants.HTTP_URL_LOGIN, data={
                "username": constants.username,
                "password": constants.password
            })
        except SSLError:
            logger.error("SSL Error encountered during HTTP request.")
            pytest.fail("Unexpected SSLError on HTTP.")
        assert response.status_code == 403
        assert response.json()['error'] == 'Access forbidden'
        logger.info("HTTP login test PASSED")
        
    def test_login_tls_1_3_https(self):
        """Test HTTPS login with TLS 1.3. Expect protocol error."""
        logger.info("Testing login with TLS 1.3")
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_3,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_3))

        with pytest.raises(requests.exceptions.SSLError) as excinfo:
            session.post(
                constants.HTTPS_URL_LOGIN,
                data={"username": constants.username,
                      "password": constants.password},
                cert=(constants.CERT_FILE, constants.KEY_FILE),
                headers=constants.headers, verify=constants.CA_FILE
                )

        assert "tlsv1 alert protocol version" in str(excinfo.value)
        logger.info("TLS 1.3 login test PASSED")
        
    def test_login_tls_1_2_https(self):
        """Test HTTPS login with TLS 1.2. Expect successful authentication."""
        logger.info("Testing login with TLS 1.2")
        
        secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
        logger.debug(f"clent secret key:  {secret_key}")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        header = conftest.get_headers({"X-Verification-Code":verification_code})

        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))

        response = session.post(
                                constants.HTTPS_URL_LOGIN,
                                json={"username": constants.username, "password": constants.password}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=header, verify=constants.CA_FILE)

        assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
        json_data = response.json()
        assert 'access_token' in json_data, "'access_token' missing in response"
        assert 'refresh_token' in json_data, "'refresh_token' missing in response"
        logger.info("TLS 1.2 login test PASSED")
        
    def test_login_tls_1_2_https_by_email(self):
        """
        Test logging in using TLS 1.2 with HTTPS and valid credentials (email).
        Verifies that the access and refresh tokens are returned successfully.
        """
        logger.info("Starting test_login_tls_1_2_https_by_email")
        
        secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
        logger.debug(f"clent secret key:  {secret_key}")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        header = conftest.get_headers({"X-Verification-Code":verification_code})
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))

        response = session.post(
                                constants.HTTPS_URL_LOGIN,
                                json={"username": constants.email, "password": constants.password}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=header, verify=constants.CA_FILE)
        
        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response data: {response.json()}")

        assert response.status_code == 200
        assert 'access_token' in response.json()
        assert 'refresh_token' in response.json()
        logger.info("test_login_tls_1_2_https_by_email PASSED")
        
    def test_login_tls_1_2_https_accept_html(self):
        """
        Test logging in using TLS 1.2 with HTTPS when 'Accept' header is set to 'text/html'.
        Verifies that login fails with status 403 and appropriate error message.
        """
        logger.info("Starting test_login_tls_1_2_https_accept_html")
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))
        
        header = conftest.get_headers({"Accept":"text/html"})
        response = session.post(
                                constants.HTTPS_URL_LOGIN,
                                json={"username": constants.email, "password": constants.password}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=header, verify=constants.CA_FILE)
        
        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response data: {response.content}")

        assert response.status_code == 403
        assert 'Browser access not allowed' in response.content.decode()

        logger.info("test_login_tls_1_2_https_accept_html PASSED")
  
    def test_login_tls_1_2_https_wrong_user(self):
        """
        Test logging in using TLS 1.2 with HTTPS and incorrect username.
        Verifies that login fails with status 403 and appropriate error message.
        """
        logger.info("Starting test_login_tls_1_2_https_wrong_user")
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))

        response = session.post(
                                constants.HTTPS_URL_LOGIN,
                                json={"username": "wrong user", "password": constants.password}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=constants.headers, verify=constants.CA_FILE)
        
        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response data: {response.json()}")

        assert response.status_code == 403
        assert 'Incorrect user' in response.json()['error']
        
        logger.info("test_login_tls_1_2_https_wrong_user PASSED")
        
    def test_login_tls_1_2_https_wrong_Cert(self):
        """
        Test login with TLS 1.2 using an invalid client certificate.
        The server should deny access with a 401 status code and return an appropriate error message.
        """
        logger.info("Starting test_login_tls_1_2_https_wrong_Cert")
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))

        response = session.post(
                                constants.HTTPS_URL_LOGIN,
                                json={"username": constants.username, "password": constants.password}, 
                                cert=(constants.WRONG_CERT_FILE, constants.KEY_FILE),
                                headers=constants.headers, verify=constants.CA_FILE)
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response content: {response.content}")

        assert response.status_code == 401
        assert 'not a valid user' in response.json()['error']
        
        logger.info("test_login_tls_1_2_https_wrong_Cert PASSED")
        
    def test_login_tls_1_2_https_wrong_data(self):
        """
        Test login with TLS 1.2 using incorrect user data.
        The server should return a 400 status code indicating a bad request with an appropriate error message.
        """
        logger.info("Starting test_login_tls_1_2_https_wrong_data")
        
        secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
        logger.debug(f"clent secret key:  {secret_key}")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        header = conftest.get_headers({"X-Verification-Code":verification_code})
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))

        response = session.post(
                                constants.HTTPS_URL_LOGIN,
                                json={"username": constants.username, "password": constants.password,"other":"otherdata"}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=header, verify=constants.CA_FILE)
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response content: {response.content}")

        assert response.status_code == 400
        assert 'Incorrect data' in response.json()['error']
        
        logger.info("test_login_tls_1_2_https_wrong_data PASSED")
        
    def test_login_tls_1_2_https_wrong_password(self):
        """
        Test login with TLS 1.2 using an empty password field.
        The server should return a 400 status code and indicate missing credentials in the error message.
        """
        logger.info("Starting test_login_tls_1_2_https_wrong_password")
        secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
        logger.debug(f"clent secret key:  {secret_key}")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        header = conftest.get_headers({"X-Verification-Code":verification_code})
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))

        response = session.post(
                                constants.HTTPS_URL_LOGIN,
                                json={"username": constants.username, "password": ''}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=header, verify=constants.CA_FILE)
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response content: {response.content}")

        assert response.status_code == 400
        assert 'Missing credentials' in response.json()['error']
        
        logger.info("test_login_tls_1_2_https_wrong_password PASSED")

    def test_login_tls_1_1_https(self):
        """
        Test login with TLS 1.1. The server should reject the connection and raise an SSLError.
        """
        logger.info("Starting test_login_tls_1_1_https")
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_1))
        with pytest.raises(requests.exceptions.SSLError) as excinfo:
            response = session.post(constants.HTTPS_URL_LOGIN, data={"username": constants.username, "password": constants.password}, cert=(constants.CERT_FILE, constants.KEY_FILE), headers=constants.headers, verify=constants.CA_FILE)

        logger.info(f"SSLError raised: {excinfo.value}")
        assert "tlsv1 alert protocol version" in str(excinfo.value)
        
        logger.info("test_login_tls_1_1_https PASSED")
        
    def test_wrong_host_https(self):
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))

        response = session.post(
                                constants.HTTPS_WRONG_HOST_URL,
                                json={"username": constants.email, "password": constants.password}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=constants.headers, verify=constants.CA_FILE)
        
        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response content: {response.content}")

        assert response.status_code == 403

    def test_login_tls_1_2_https_multiple_times(self):
        """
        Test multiple login attempts with TLS 1.2.
        The server should handle multiple requests without issues and return an access token for each successful login.
        """
        logger.info("Starting test_login_tls_1_2_https_multiple_times")
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(
            ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
            ssl_maximum_version=ssl.TLSVersion.TLSv1_2
        ))
        
        header = conftest.get_headers({"Referer":"https://sessionid:8080/login/"})
        
        for i in range(10): 
            logger.info(f"Attempt {i + 1}/10")
            
            secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
            logger.debug(f"clent secret key:  {secret_key}")
            totp = pyotp.TOTP(secret_key)
            verification_code = totp.now()
            
            header["X-Verification-Code"] = verification_code

            response = session.post(
                constants.HTTPS_URL_LOGIN,
                json={"username": constants.username, "password": constants.password},
                cert=(constants.CERT_FILE, constants.KEY_FILE),
                headers=header,
                verify=constants.CA_FILE
            )
            
            csrf_token = response.cookies.get('csrftoken')
            
            header["X-CSRFToken"] = csrf_token

            logger.info(f"Response content for attempt {i + 1}: {response.content}")
            
            assert response.status_code == 200, f"Failed on attempt {i + 1}"
            json_data = response.json()
            assert 'access_token' in json_data, f"Missing 'access_token' on attempt {i + 1}"
            assert 'refresh_token' in json_data, f"Missing 'refresh_token' on attempt {i + 1}"

        logger.info("All 10 attempts passed successfully!")
        
    def test_logout_https(self):
        """
        Test logout functionality over HTTPS with valid credentials.
        1. Logs in with valid credentials.
        2. Logs out using the returned access token.
        3. Verifies that the logout response is successful.
        """

        logger.info("Starting test_logout_https")
        
        secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
        logger.debug(f"clent secret key:  {secret_key}")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        header = conftest.get_headers({"X-Verification-Code":verification_code})
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))
        
        login = session.post(
                            constants.HTTPS_URL_LOGIN,
                            json={"username": constants.username, "password": constants.password}, 
                            cert=(constants.CERT_FILE, constants.KEY_FILE),
                            headers=header, verify=constants.CA_FILE
                            )

        assert login.status_code == 200
        logger.info("Login successful, status code: %d", login.status_code)

        access_token_header ={"Authorization": f"Bearer {login.json().get('access_token')}"}
        auth_headers = conftest.get_headers(access_token_header)

        response = session.post(
                                constants.HTTPS_URL_LOGOUT, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE), 
                                headers=auth_headers, verify=constants.CA_FILE
                                )

        assert response.status_code == 200
        assert "message" in response.json()
        assert response.json().get('message') == "Successfully logged out"
        
        logger.info("test_logout_https PASSED")
        
    def test_logout_wrong_token_https(self):
        """
        Test logout functionality over HTTPS using an invalid token.
        
        Steps:
        1. Perform a valid login to verify the service is working.
        2. Attempt to log out using an invalid access token.
        3. Verify that the server responds with an appropriate error message and status code.
        """

        logger.info("Starting test_logout_wrong_token_https")
        
        secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
        logger.debug(f"clent secret key:  {secret_key}")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        header = conftest.get_headers({"X-Verification-Code":verification_code})
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))
        
        login = session.post(
                            constants.HTTPS_URL_LOGIN,
                            json={"username": constants.username, "password": constants.password}, 
                            cert=(constants.CERT_FILE, constants.KEY_FILE),
                            headers=header, verify=constants.CA_FILE
                            )

        assert login.status_code == 200
        logger.info("Login successful, status code: %d", login.status_code)

        access_token_header ={"Authorization": "Bearer wrongToken"}
        auth_headers = conftest.get_headers(access_token_header)

        logger.info("Attempting to logout with an invalid token")
        response = session.post(
                                constants.HTTPS_URL_LOGOUT, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE), 
                                headers=auth_headers, verify=constants.CA_FILE
                                )
        
        logger.info(f"Response status code: {response.status_code}")
        logger.debug(f"Response headers: {response.headers}")
        logger.debug(f"Response content: {response.content}")

        assert response.status_code == 401
        assert "No valid Access token" in response.json()['error']
        
        logger.info("test_logout_wrong_token_https PASSED")
        
    def test_logout_wrong_cert_https(self):
        """
        Test logout functionality over HTTPS using an invalid certificate.

        Steps:
        1. Perform a valid login to verify the service is working.
        2. Attempt to log out using a wrong certificate while providing valid headers.
        3. Verify that the server responds with an appropriate error message and status code.
        """

        logger.info("Starting test_logout_wrong_cert_https")
        
        secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
        logger.debug(f"clent secret key:  {secret_key}")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        header = conftest.get_headers({"X-Verification-Code":verification_code})
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))
        
        login = session.post(
                            constants.HTTPS_URL_LOGIN,
                            json={"username": constants.username, "password": constants.password}, 
                            cert=(constants.CERT_FILE, constants.KEY_FILE),
                            headers=header, verify=constants.CA_FILE
                            )

        assert login.status_code == 200
        logger.info("Login successful, status code: %d", login.status_code)

        access_token_header ={"Authorization": f"Bearer wrongToken"}
        auth_headers = conftest.get_headers(access_token_header)

        logger.info("Attempting to logout with an invalid token")
        response = session.post(
                                constants.HTTPS_URL_LOGOUT, 
                                cert=(constants.WRONG_CERT_FILE, constants.KEY_FILE), 
                                headers=auth_headers, verify=constants.CA_FILE
                                )
        
        logger.info(f"Response status code: {response.status_code}")
        logger.debug(f"Response headers: {response.headers}")
        logger.debug(f"Response content: {response.content}")

        assert response.status_code == 401
        assert "not a valid user" in response.json()['error']
        
        logger.info("test_logout_wrong_cert_https PASSED")
        
    def test_refresh_https(self):
        """
        Test token refresh functionality over HTTPS.
        1. Logs in to obtain access and refresh tokens.
        2. Refreshes the access token using the refresh token.
        3. Verifies that the new tokens are returned.
        """

        logger.info("Starting test_refresh_https")
        
        secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
        logger.debug(f"clent secret key:  {secret_key}")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        header = conftest.get_headers({"X-Verification-Code":verification_code})
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                            ssl_maximum_version=ssl.TLSVersion.TLSv1_2))
        
        login = session.post(
                                constants.HTTPS_URL_LOGIN,
                                json={"username": constants.username, "password": constants.password}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=header, verify=constants.CA_FILE)

        assert login.status_code == 200
        logger.info("Login successful, status code: %d", login.status_code)

        access_token = login.json().get('access_token')
        refresh_token = login.json().get('refresh_token')
        
        access_token_header ={"Authorization": f"Bearer {access_token}"}
        auth_headers = conftest.get_headers(access_token_header)

        response = session.post(
                                constants.HTTPS_URL_REFRESH,
                                json={"refresh_token": refresh_token}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=auth_headers, verify=constants.CA_FILE)

        assert response.status_code == 200
        assert 'access_token' in response.json()
        assert 'refresh_token' in response.json()
        
        logger.info("test_refresh_http PASSED")
        
    def test_login_concurrent(self):
        """
        Test concurrent login requests to verify that the system handles them correctly.
        1. Initiates multiple concurrent login requests.
        2. Verifies that each request returns unique tokens.
        3. Logs out using one of the access tokens.
        """

        logger.info("Starting test_login_concurrent")
        
        session = requests.Session()
        session.mount('https://', conftest.CustomTLSAdapter(
            ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
            ssl_maximum_version=ssl.TLSVersion.TLSv1_2
        ))

        num_requests = 3  
        results = []
        access_tokens = set()
        refresh_tokens = set()
        
        logger.info(f"Sending {num_requests} concurrent login requests...")
        time.sleep(2)
        
        secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
        logger.debug(f"clent secret key:  {secret_key}")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        header = conftest.get_headers({"X-Verification-Code":verification_code})
        
        with ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [
                executor.submit(self.send_request, session, constants.HTTPS_URL_LOGIN, constants.username, constants.password, header)
                for _ in range(num_requests)
            ]

            for future in as_completed(futures):
                logger.debug(f"task completed with result {future.result()}")
                logger.debug(f"Response status code: {future.result().status_code}")
                logger.debug(f"Response content: {future.result().content}")
                results.append(future.result())

        for result in results:
            json_data = result.json()
            if result.status_code == 200:
                access_tokens.add(json_data['access_token'])
                refresh_tokens.add(json_data['refresh_token'])
            
        assert len(access_tokens) == 1, "Duplicate access_token detected!"
        assert len(refresh_tokens) == 1, "Duplicate refresh_token detected!"
        
        logger.info("Concurrent login test passed, unique tokens received")
        
        # Perform logout using one of the access tokens
        logger.info("Attempting to logout")
        access_token_header ={"Authorization": f"Bearer {next(iter(access_tokens))}"}
        auth_headers = conftest.get_headers(access_token_header)
        
        response = session.post(constants.HTTPS_URL_LOGOUT, cert=(constants.CERT_FILE, constants.KEY_FILE), headers=auth_headers, verify=constants.CA_FILE)
        assert response.status_code == 200
        
        logger.info("Logout successful, status code: %d", response.status_code)
        
        logger.info("test_login_concurrent PASSED")
        
        
    def test_life_cycle(self):
        """
        Test the full lifecycle of login, token refresh, and logout over HTTPS.

        Steps:
        1. Repeat the process 10 times to validate stability.
        2. Login to obtain access and refresh tokens.
        3. Refresh the token using the refresh token.
        4. Log out using the refreshed access token.
        5. Verify that all operations return the expected status and responses.
        """
        logger.info("Starting test_life_cycle")
        
        for i in range(10): 
            logger.info(f"Attempt {i + 1}/10")
            
            secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
            logger.debug(f"clent secret key:  {secret_key}")
            totp = pyotp.TOTP(secret_key)
            verification_code = totp.now()
            
            header = conftest.get_headers({"X-Verification-Code":verification_code})
        
            session = requests.Session()
            session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                                ssl_maximum_version=ssl.TLSVersion.TLSv1_2))
            
            login = session.post(
                                    constants.HTTPS_URL_LOGIN,
                                    json={"username": constants.username, "password": constants.password}, 
                                    cert=(constants.CERT_FILE, constants.KEY_FILE),
                                    headers=header, verify=constants.CA_FILE)

            assert login.status_code == 200
            logger.info("Login successful, status code: %d", login.status_code)

            access_token = login.json().get('access_token')
            refresh_token = login.json().get('refresh_token')
            
            # Step 2: Refresh the token
            logger.info("Attempting token refresh")
            access_token_header ={"Authorization": f"Bearer {access_token}"}
            auth_headers = conftest.get_headers(access_token_header)

            refresh = session.post(
                                    constants.HTTPS_URL_REFRESH,
                                    json={"refresh_token": refresh_token}, 
                                    cert=(constants.CERT_FILE, constants.KEY_FILE),
                                    headers=auth_headers, verify=constants.CA_FILE)

            assert refresh.status_code == 200
            assert 'access_token' in refresh.json()
            assert 'refresh_token' in refresh.json()
            
            access_token = refresh.json().get('access_token')
            
            # Step 3: Logout
            logger.info("Attempting logout")
            access_token_header ={"Authorization": f"Bearer {access_token}"}
            auth_headers = conftest.get_headers(access_token_header)

            response = session.post(
                                    constants.HTTPS_URL_LOGOUT, 
                                    cert=(constants.CERT_FILE, constants.KEY_FILE), 
                                    headers=auth_headers, verify=constants.CA_FILE
                                    )

            assert response.status_code == 200
            assert "message" in response.json()
            assert response.json().get('message') == "Successfully logged out"
            
            logger.info(f"Lifecycle attempt {i + 1}/10 completed successfully")
            
        logger.info("test_life_cycle PASSED")
        
    def test_login_too_many_attempts_https(self):
        """
        Test the login endpoint to ensure that after too many failed login attempts,
        further attempts are blocked, and a 429 status code is returned.
        """

        logger.info("Starting test: test_login_too_many_attempts_https")

        for i in range(3):
            logger.info(f"Attempt {i + 1}: Sending login request with incorrect password.")
            
            secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
            logger.debug(f"clent secret key:  {secret_key}")
            totp = pyotp.TOTP(secret_key)
            verification_code = totp.now()
            
            header = conftest.get_headers({"X-Verification-Code":verification_code})
            
            session = requests.Session()
            session.mount('https://', conftest.CustomTLSAdapter(ssl_minimum_version=ssl.TLSVersion.TLSv1_1,
                                                                ssl_maximum_version=ssl.TLSVersion.TLSv1_2))
            response = session.post(
                                constants.HTTPS_URL_LOGIN,
                                json={"username": constants.username, "password": f'wrongpass{i}'}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=header, verify=constants.CA_FILE)
            
            logger.debug(f"Response status code: {response.status_code}")
            logger.debug(f"Response content: {response.content}")
            
            time.sleep(3)
            
        secret_key = TwoFactor.generate_secret_key(constants.email, constants.username)
        logger.debug(f"clent secret key:  {secret_key}")
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        header = conftest.get_headers({"X-Verification-Code":verification_code})

        response = session.post(
                                constants.HTTPS_URL_LOGIN,
                                json={"username": constants.username, "password": constants.password}, 
                                cert=(constants.CERT_FILE, constants.KEY_FILE),
                                headers=header, verify=constants.CA_FILE)
        
        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response content: {response.content}")
        assert response.status_code == 429
        
        logger.info("Test passed: User is correctly blocked after too many failed login attempts.")
        
        



        





 
    

        
    