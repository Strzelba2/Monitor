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
import json
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

    
def get_headers(kwargs: dict) -> dict:
    """
    Constructs and returns a dictionary of HTTP headers by merging default headers 
    with the headers provided in the `kwargs` parameter. 
    
    If a header key already exists in the default headers, its value will be updated 
    with the value provided in `kwargs`. Any additional headers in `kwargs` that are 
    not part of the default headers will be added to the resulting dictionary.

    :param kwargs: A dictionary of headers to override or add to the defaults.
    :return: A dictionary containing the updated headers.
    """
    logger.debug(f"Setting up additional headers in request:  {kwargs}")
    header = headers.copy() 
    for key in list(kwargs.keys()):  
        if key in header:  
            header[key] = kwargs.pop(key)  
    return {**header, **kwargs} 


def set_client_secret(username: str) -> None:
    """
    Set a client secret for a given username by executing a command in the Docker container.

    This function runs a `manage.py` command inside a Docker container to set the client secret
    for the specified username. The secret is retrieved from the command output.

    Args:
        username (str): The username for which the client secret is to be set.

    Raises:
        RuntimeError: If the command execution fails.
    """
    logger.debug(f"Fetching client secret for username: {username}")
    command = [
        "docker", "exec", "my_apache", "python", "manage.py", "set_client_secret", username
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        client_secret = result.stdout.strip().split(":")[-1] 
        logger.info(f"Client secret {client_secret} seted successfully for username: {username}")

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
        
    try:
        set_client_secret(username)
    except Exception as e:
        logger.error(f"Error while setting hasehed secret for '{username}': {e}")
        assert False, f"Failed to set hashed secret for '{username}': {e}"
        
  
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

