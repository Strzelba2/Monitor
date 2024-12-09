import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SESSION_SERVER_LOGIN_URL = os.getenv("SESSION_SERVER_LOGIN_URL")
    DATABASE_URL = os.getenv("DATABASE_URLY")
    SESSION_EXPIRATION_HOURS = os.getenv("SESSION_EXPIRATION_HOURS")
    TOKEN_EXPIRATION_MINUTES = os.getenv("TOKEN_EXPIRATION_MINUTES")
    REFRESH_EXPIRATION_HOURS = os.getenv("REFRESH_EXPIRATION_HOURS")
    

