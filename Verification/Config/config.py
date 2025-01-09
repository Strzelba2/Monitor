import os
from robot.api import logger
from Verification.Config.constants import *

class Config:
    """
    Configuration class for managing environment variables for Session Server and Client.

    This class provides methods to set and update environment variables by writing them
    to `.env` files located in predefined paths.
    """
    
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    env_session_server__file_path = os.path.join(BASE_DIR,"sessionServer",".env")
    env_client_file_path = os.path.join(BASE_DIR,"Client","config",".env")
    
    @classmethod
    def _set_env(cls,env_data:dict, path:str) -> None:
        """
        Updates or creates an `.env` file with the provided environment variables.

        Args:
            env_data (dict): A dictionary containing the environment variables to set.
            path (str): The file path where the `.env` file is located.

        Raises:
            None: This method handles exceptions internally by logging the error.
        """
        logger.info(f"Updating environment variables at path: {path}")
        env_variables = {}
        if os.path.exists(path):
            with open(path, "r") as env_file:
                for line in env_file:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        env_variables[key] = value
        
        env_variables.update(env_data)
        
        with open(path, "w") as env_file:
            for key, value in env_variables.items():
                env_file.write(f"{key}={value}\n")
                
        logger.info("Environment variables updated successfully.")
    
    @classmethod
    def set_session_server_env(cls) -> None:
        """
        Sets environment variables for the Session Server by updating its `.env` file.

        Raises:
            None: This method does not explicitly raise exceptions.
        """
        logger.debug("Setting environment variables for Session Server.")
        
        env_data = {
        "TEST_USER_USERNAME": USERNAME,
        "TEST_USER_PASSWORD": PASSWORD,
        "TEST_USER_LASTNAME":LASTNAME,
        "TEST_USER_FIRSTNAME":FIRSTNAME,
        "TEST_USER_EMAIL":EMAIL,
        "TEST_CLIENT_ID": CLIENT_ID,
        "TEST_CLIENT_SECRET": CLIENT_SECRET,
        "RUN_TEST_SETUP":"true",
        }
        
        cls._set_env(env_data, cls.env_session_server__file_path)
        
    @classmethod
    def set_client_env(cls) -> None:
        """
        Sets environment variables for the Client by updating its `.env` file.

        Raises:
            None: This method does not explicitly raise exceptions.
        """
        logger.debug("Setting environment variables for Client.")
        
        env_data = {
            "DATABASE_URL":DATABASE_URL,
            "SESSION_EXPIRATION_HOURS":SESSION_EXPIRATION_HOURS,
            "TOKEN_EXPIRATION_MINUTES":TOKEN_EXPIRATION_MINUTES,
            "REFRESH_EXPIRATION_HOURS":REFRESH_EXPIRATION_HOURS,
            "CA_PATH":CA_PATH,
            "CERT_PATH":CERT_PATH,
            "KEY_PATH":KEY_PATH,
            "DOMAIN":DOMAIN,
            "REQUEST_TIMEOUT":REQUEST_TIMEOUT,
            "REFRESH_TOKEN_TIME_DELTA":REFRESH_TOKEN_TIME_DELTA,
            "EXCEPTION_EVENT_FILE":EXCEPTION_EVENT_FILE,
        }
        
        cls._set_env(env_data, cls.env_client_file_path)
        
        
        
        
        
        