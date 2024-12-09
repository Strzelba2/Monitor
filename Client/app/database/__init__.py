from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = "sqlite:///app_data.db"

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    """
    Initializes the database by creating all necessary tables.
    """
    try:
        # Check if tables exist and create them if not
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully.")
    except OperationalError as e:
        logger.error(f"Database initialization failed: {e}")
        raise