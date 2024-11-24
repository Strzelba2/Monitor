import os
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import pytest
from constants import *
import hmac
import hashlib
from secret_provider import SecretProvider
import time
from decouple import config
import requests
import subprocess
import base64
import ssl
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class CustomTLSAdapter(HTTPAdapter):
    def __init__(self, 
                 ssl_minimum_version: Optional[ssl.TLSVersion] = None, 
                 ssl_maximum_version: Optional[ssl.TLSVersion] = None, 
                 *args, **kwargs) -> None:
        """
        Initializes a custom TLS adapter with optional minimum and maximum TLS versions.
        
        :param ssl_minimum_version: Minimum TLS version (default is None)
        :param ssl_maximum_version: Maximum TLS version (default is None)
        """
        
        self.ssl_minimum_version = ssl_minimum_version
        self.ssl_maximum_version = ssl_maximum_version
        super().__init__(*args, **kwargs)
        logger.info(f"Initialized CustomTLSAdapter with min version: {ssl_minimum_version}, max version: {ssl_maximum_version}")

    def init_poolmanager(self, *args, **kwargs) -> object:
        """
        Initializes the pool manager with a custom SSL context.
        
        :param args: Additional arguments
        :param kwargs: Additional keyword arguments
        :return: A pool manager instance
        """
        logger.debug("Initializing pool manager with custom SSL context.")

        context = create_urllib3_context(
            ssl_minimum_version=self.ssl_minimum_version,
            ssl_maximum_version=self.ssl_maximum_version
        )
        if self.ssl_minimum_version == ssl.TLSVersion.TLSv1:
            context.options &= ~ssl.OP_NO_TLSv1_3 & ~ssl.OP_NO_TLSv1_2 & ~ssl.OP_NO_TLSv1_1
            context.set_ciphers('HIGH:!aNULL:!eNULL')

        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)
    
    def send(self, request, **kwargs) -> object:
        """
        Sends the HTTP request and logs the TLS version used for the connection.
        
        :param request: The HTTP request object
        :param kwargs: Additional keyword arguments for the request
        :return: The response object
        """
        logger.debug(f"Sending request: {request.method} {request.url}")
        response = super().send(request, **kwargs)

        # Retrieve the underlying socket and get the TLS version
        sock = response.raw._connection.sock
        if sock:
            tls_version = sock.version()
            logger.info(f'TLS version used for connection: {tls_version}')

        return response
    
def generate_hmac(session_id: str, ip_address: str, method: str, timestamp: str, username: str, body: str, secret_key: str) -> str:
    """
    Generates an HMAC signature.

    :param session_id: Session ID
    :param ip_address: Server IP address
    :param method: HTTP method (e.g., 'GET', 'POST')
    :param timestamp: Current timestamp
    :param username: Username
    :param body: Request body
    :param secret_key: Secret key for HMAC
    :return: Base64-encoded HMAC signature
    """
    
    logger.debug(f"Generating HMAC for session: {session_id}, username: {username}")
    # Encode the body using Base64
    encoded_body = base64.b64encode(body.encode()).decode()

    # Create the message by concatenating the components
    message = f"{session_id}{ip_address}{method}{timestamp}{username}{encoded_body}"

    # Generate the HMAC signature
    hmac_signature = hmac.new(secret_key.encode(), message.encode(), hashlib.sha256).hexdigest()

    # Encode the HMAC signature using Base64
    encoded_hmac_signature = base64.b64encode(hmac_signature.encode()).decode()

    logger.info("HMAC signature generated successfully.")
    return encoded_hmac_signature


def set_env() -> None:
    """
    Updates environment variables for the test setup.
    
    Reads existing environment variables from a file, updates them with test-specific values, 
    and writes them back to the file.
    """
    logger.debug("Setting environment variables for test setup.")
    
    env_data = {
    "TEST_USER_USERNAME": username,
    "TEST_USER_PASSWORD": password,
    "TEST_USER_LASTNAME":lastname,
    "TEST_USER_FIRSTNAME":firstname,
    "TEST_USER_EMAIL":email,
    "TEST_CLIENT_ID": client_id,
    "TEST_CLIENT_SECRET": client_secret,
    "RUN_TEST_SETUP":"true"
    }
    
    env_variables = {}
    if os.path.exists(env_file_path):
        with open(env_file_path, "r") as env_file:
            for line in env_file:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    env_variables[key] = value
    
    env_variables.update(env_data)
    
    with open(env_file_path, "w") as env_file:
        for key, value in env_variables.items():
            env_file.write(f"{key}={value}\n")
            
    logger.info("Environment variables updated successfully.")

def get_headers(token: str) -> dict:
    """
    Constructs headers for an HTTP request, including the Authorization token.

    :param token: Bearer token for authentication
    :return: A dictionary of HTTP headers
    """
    logger.debug(f"Creating headers with token: {token}")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        'X-Forwarded-For': '203.0.113.195',
    }


def get_client_secret(username: str) -> str:
    """
    Retrieves the client secret from a Docker container.

    :param username: Username for which to retrieve the secret
    :return: The client secret for the user
    """
    logger.debug(f"Fetching client secret for username: {username}")
    command = [
        "docker", "exec", "my_apache", "python", "manage.py", "get_client_secret", username
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        client_secret = result.stdout.strip().split(":")[-1] 
        logger.info(f"Client secret retrieved successfully for username: {username}")
        return client_secret
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e.stderr}")
        raise RuntimeError(f"Command failed: {e.stderr}")
    
def create_user_certyficate(username: str) -> str:
    """
    Creates a certificate for the given username within a Docker container.

    :param username: The username for which to create the certificate
    :return: The output of the certificate creation process
    """
    logger.debug(f"Creating user certificate for username: {username}")
    command = [
        "docker", "exec", "my_apache", "python", "manage.py", "create_cert", username
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip() 
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e.stderr}")
        raise RuntimeError(f"Command failed: {e.stderr}")
    
def copy_file_from_container(container_path: str, local_path: str) -> str:
    """
    Copies a file from a Docker container to the local filesystem.

    :param container_path: Path to the file in the container.
    :param local_path: Path to the destination on the local machine.
    :return: Success message indicating the local path of the copied file.
    :raises RuntimeError: If the file copy operation fails.
    """
    logger.info(f"Attempting to copy file from container: {container_path} to local path: {local_path}")
    try:
        subprocess.run(
            ["docker", "cp", f"my_apache:{container_path}", local_path],
            check=True
        )
        message = f"File copied to {local_path}"
        logger.info(message)
        return message
    except subprocess.CalledProcessError as e:
        error_message = f"Error copying file: {e}"
        logger.error(error_message)
        raise RuntimeError(error_message)
    

def remove_user_by_username(username: str) -> str:
    """
    Removes a user in the application by their username.

    :param username: Username of the user to remove.
    :return: Result message from the removal operation.
    :raises RuntimeError: If the removal operation fails.
    """
    logger.info(f"Attempting to remove user: {username}")
    command = [
        "docker", "exec", "my_apache", "python", "manage.py", "remove_user", username
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()  
    except subprocess.CalledProcessError as e:
        error_message = f"Failed to remove user '{username}': {e.stderr}"
        logger.error(error_message)
        raise RuntimeError(error_message)


@pytest.fixture(scope="session")
def docker_services():
    """
    Pytest fixture to start Docker services for testing.
    Also sets up necessary environment variables, creates user certificates, 
    and cleans up after tests.
    """
    logger.info("Starting Docker containers and setting up environment")
    set_env()

    # Start the Docker containers
    subprocess.run(["docker-compose", "up", "--build", "-d"], check=True)
    
    # Wait a bit for the services to be up and ready  
    time.sleep(30)
    try:
        result = create_user_certyficate(username)
        assert "certificate for the user" in result
        logger.info(f"User certificate created successfully: {result}")
    except Exception as e:
        logger.error(f"Error while creating user '{username}' certificate: {e}")
        assert False, f"Failed to create user '{username}'cartyficate : {e}"
        
    try:
        result = copy_file_from_container(DOCKER_CLIENT_CERT,CERT_FILE)
        assert "File copied to" in result
        logger.info(f"File copied successfully: {result}")
    except Exception as e:
        logger.error(f"Error copying file for user '{username}': {e}")
        assert False, f"Failed copie File to '{username}' : {e}"
  
    yield 
    
    #time allotted to collect logs in loki
    # time.sleep(60)
    
    logger.info("Stopping Docker containers and removing resources")
    try:
        result = remove_user_by_username(username)
        assert "Successfully deleted user" in result
        logger.info(f"User removed successfully: {result}")
    except Exception as e:
        logger.error(f"Error while removing user '{username}': {e}")
        assert False, f"Failed to remove user '{username}': {e}"
        
    # Stop and remove the Docker containers
    subprocess.run(["docker-compose", "down"], check=True)
    


@pytest.fixture(scope="session")
def secret_provider(docker_services):
    """
    Pytest fixture to set up a secret provider for testing.
    Starts a secret handler process and verifies its health before tests.
    """
    logger.info("Setting up SecretProvider")
    hashed_secret = get_client_secret(username)
    logger.info(f"Hashed secret retrieved: {hashed_secret}")

    secret_handler = SecretProvider(int(config('SECRET_SERVER_URL_LOCAL').split(":")[2]),hashed_secret)
    
    secret_handler.start()

    # Check if SecretProvider is running
    time.sleep(10) 
    try:
        response = requests.get(f'{config('SECRET_SERVER_URL_LOCAL')}/health', cert=(CERT_FILE, KEY_FILE), verify=CA_FILE)
        assert response.status_code == 200
        logger.info("SecretProvider is running")
    except Exception as e:
        logger.error(f"SecretProvider failed to start: {e}")
        secret_handler.terminate()
        pytest.fail("Failed to start SecretProvider")

    yield secret_handler

    logger.info("Tearing down SecretProvider")
    if secret_handler.is_alive():
        secret_handler.terminate()
        
        
@pytest.fixture(scope="function", autouse=True)
def clear_tokens():
    """
    Pytest fixture to clear access and refresh tokens for a user after each test.
    Automatically applied to all tests.
    """
    yield 

    logger.info("Clearing tokens")
    command = [
        "docker", "exec", "my_apache", "python", "manage.py", "clear_tokens", username
    ]
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        message = result.stdout.strip()
        logger.info(f"Tokens cleared successfully: {message}")
    except subprocess.CalledProcessError as e:
        error_message = f"Failed to clear tokens: {e.stderr}"
        logger.error(error_message)
        raise RuntimeError(error_message)

