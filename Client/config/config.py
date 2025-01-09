import os
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)
load_dotenv()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

logger.info(f"BASE_DIR:  {BASE_DIR}")

class Config:
    """
    Configuration class for managing application settings.

    This class retrieves configuration values from environment variables
    and defines constants used throughout the application. It provides
    centralized management of settings for database connections, session
    handling, token expiration, and file paths for certificates and exception
    logging.
    """

    DATABASE_URL = os.getenv("DATABASE_URL")
    SESSION_EXPIRATION_HOURS = os.getenv("SESSION_EXPIRATION_HOURS")
    TOKEN_EXPIRATION_MINUTES = os.getenv("TOKEN_EXPIRATION_MINUTES")
    REFRESH_EXPIRATION_HOURS = os.getenv("REFRESH_EXPIRATION_HOURS")
    REQUEST_TIMEOUT = os.getenv("REQUEST_TIMEOUT")
    REFRESH_TOKEN_TIME_DELTA = os.getenv("REFRESH_TOKEN_TIME_DELTA")
    EXCEPTION_EVENT_FILE = os.path.join(BASE_DIR,"Client","app","exceptions",os.getenv("EXCEPTION_EVENT_FILE"))
    DOMAIN = os.getenv("DOMAIN")
    CA_PATH = os.path.join(BASE_DIR,"sessionServer","cert","new",os.getenv("CA_PATH"))
    CERT_PATH = os.path.join(BASE_DIR,"sessionServer","cert","new",os.getenv("CERT_PATH"))
    KEY_PATH =os.path.join(BASE_DIR,"sessionServer","cert","new",os.getenv("KEY_PATH")) 
    
    HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
    }
    

