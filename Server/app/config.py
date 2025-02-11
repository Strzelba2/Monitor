import os
import logging

logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

logger.info(f"BASE_DIR:  {BASE_DIR}")

class Config:
    """
    Configuration class for application settings.

    This class contains constants used throughout the application, including 
    session server settings, Redis configuration, security credentials, and 
    connection parameters.
    """
    SESSION_SERVER_URL = "http://session-server.example.com"
    CONNECTION_COUNT_KEY = "connection_count"
    MAX_CONNECTIONS = 4
    REDIS_URL = "redis://localhost"
    SERVER_NAME = "Server_1"
    REQUEST_TIMEOUT = 15
    DOMAIN="SessionID:8080"
    CA_PATH = os.path.join(BASE_DIR,"cert","ca.crt")
    CERT_PATH = os.path.join(BASE_DIR,"cert","server.crt")
    KEY_PATH =os.path.join(BASE_DIR,"cert","server.key") 
    
    HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
    }
    
    