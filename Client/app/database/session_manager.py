from app.database import SessionLocal
from app.database.models import SessionData
from app.database.base import BaseManager, SingletonMeta
from datetime import datetime, timezone, timedelta
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from app.exceptions.database_exc import SessionManagerError
from typing import Optional, List
from config.config import Config
from cryptography.fernet import InvalidToken
import logging

logger = logging.getLogger(__name__)



class SessionManager(BaseManager, metaclass=SingletonMeta):
    """
    Manages session data in the database, including creation, updating, 
    validation, retrieval, and listing of sessions.
    """
    def __init__(self):
        """
        Initializes the SessionManager with a database session.
        """
        super().__init__()
        self.db = SessionLocal()
        logger.info("SessionManager initialized with a database session.")
        
    def validate_session(self, created: datetime, expired: datetime) -> bool:
        """
        Validates a session's creation and expiration timestamps.

        Args:
            created (datetime): The session creation timestamp.
            expired (datetime): The session expiration timestamp.

        Returns:
            bool: True if the session timestamps are valid.

        Raises:
            ValueError: If the session timestamps are invalid.
        """
        now = datetime.now(timezone.utc)
        max_expiration_time = now + timedelta(hours=int(Config.SESSION_EXPIRATION_HOURS))
        delta = timedelta(minutes=2)
        
        if created.tzinfo is None or created.tzinfo.utcoffset(created) is None:
            logger.error(f"The 'created' timestamp must be timezone-aware.")
            raise ValueError("The 'created' timestamp must be timezone-aware.")
        if expired.tzinfo is None or expired.tzinfo.utcoffset(expired) is None:
            logger.error(f"The 'expired' timestamp must be timezone-aware.")
            raise ValueError("The 'expired' timestamp must be timezone-aware.")
        
        if  created >= now + delta:
            logger.error(f"Session creation timestamp cannot be in the future.")
            raise ValueError("Session creation timestamp cannot be in the future.")  
        if expired >= created + timedelta(hours=int(Config.SESSION_EXPIRATION_HOURS)) + delta and expired >= max_expiration_time + delta:
            logger.error(f"Session expiration timestamp is outside the allowable range.")
            raise ValueError("Session expiration timestamp is outside the allowable range.") 
        
        return True
        

    def __create_session(self, session_id: str, created: datetime, expired: datetime) -> None:
        """
        Creates a new session in the database.

        Args:
            session_id (str): The unique identifier for the session.
            created (datetime): The session creation timestamp.
            expired (datetime): The session expiration timestamp.

        Raises:
            IntegrityError: If a session with the same ID already exists.
            SQLAlchemyError: For any database-related issues.
        """
        logger.info(f"Attempting to create a new session ")

        session = SessionData(
            session_id=self.encrypt(session_id),
            created_at=created,
            expires_at=expired)
        try:
            self.db.add(session)
            self.db.commit()
            logger.info(f"Session with ID {session_id} created successfully.")
        except IntegrityError as e:
            self.db.rollback()
            logger.error(f"Integrity error while creating session with ID {session_id}: {e}")
            raise
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.critical(f"Unexpected database error: {e}")
            raise
        except InvalidToken as e:
            logger.error(f"Failed to encrypt session : {e}")
            raise 
        except Exception as e:
            self.db.rollback()
            logger.exception(f"Unknown error while creating session: {e}")
            raise
        
    def update_session(self, session_id: str, created: datetime, expired: datetime) -> None:
        """
        Updates an existing session or creates a new one if it doesn't exist.

        Args:
            session_id (str): The unique identifier for the session.
            created (datetime): The session creation timestamp.
            expired (datetime): The session expiration timestamp.

        Raises:
            SQLAlchemyError: For any database-related issues.
        """
        logger.info(f"Updating session with ID: {session_id},{created},{expired}")
        try:
            self.validate_session(created, expired)
            session = self.get_session()
            logger.info(f"session: {session}")
            if session:
                logger.info(f"session: {session.session_id}")
                logger.info(f"session: {session_id}")
                if session.session_id == session_id:
                    logger.info("The session ID is already up to date.")
                    return
                logger.info(f"Updating session ID from {session.session_id} to {session_id}.")
                session.session_id = self.encrypt(session_id)
                session.created_at = created
                session.expires_at = expired
                self.db.commit()
                logger.info(f"Session ID updated to {session_id}.")
            else:
                logger.info(f"No existing session found. Creating a new session with ID: {session_id}.")
                self.__create_session(session_id,created, expired)

        except SQLAlchemyError as e:
            logger.error(f"Database error while updating session with ID {session_id}: {e}")
            self.db.rollback()
            raise SessionManagerError(str(e))
        except InvalidToken as e:
            logger.error(f"Failed to decrypt or encrypt session : {e}")
            raise 
        except Exception as e:
            logger.exception(f"Unknown error while updating session: {e}")
            raise
            
    def get_session(self) -> Optional[SessionData]:
        """
        Retrieves the first session from the database.

        Returns:
            Optional[SessionData]: The first session found or None if no session exists.

        Raises:
            SQLAlchemyError: For any database-related issues.
        """
        logger.info("Retrieving the first session from the database.")
        now = datetime.now(timezone.utc)
        try:
            session = self.db.query(SessionData).populate_existing().first()
            if session:
                logger.info(f"Session found")
                logger.info(f"{session.expires_at.tzinfo}")
                if session.expires_at <= now:
                    try:
                        self.db.delete(session) 
                        self.db.commit() 
                        logger.info(f"Session  was deleted successfully.")
                        return None
                    except Exception :
                        self.db.rollback()  
                        logger.error(f"Failed to delete session :")
                logger.info(f"session:{session.session_id}")     
                session.session_id = self.decrypt(session.session_id)
                    
            else:
                logger.info("No session found.")
            return session
        except SQLAlchemyError as e:
            logger.error(f"Database error while retrieving the first session: {e}")
            raise
        except InvalidToken as e:
            logger.error(f"Failed to decrypt session : {e}")
            raise 
        except Exception as e:
            logger.exception(f"Unknown error while retrieving the first session: {e}")
            raise
    
    def list_all_sessions(self) -> List[SessionData]:
        """
        Retrieves all sessions from the database.

        Returns:
            List[SessionData]: A list of all session objects.
        """
        logger.info("Retrieving all sessions from the database.")
        try:
            sessions = self.db.query(SessionData).all()
            for session in sessions:
                logger.info(f"session: {session.session_id}")
                session.session_id = self.decrypt(session.session_id)    
            logger.info(f"Retrieved {len(sessions)} sessions from the database.")
            return sessions
        except SQLAlchemyError as e:
            logger.error(f"Database error while retrieving session list: {e}")
            raise
        except InvalidToken as e:
            logger.error(f"Failed to decrypt session : {e}")
            raise 
        except Exception as e:
            logger.error(f"Error retrieving session list: {e}")
            raise
        
    def clean_sessions(self):
        try:
            self.db.query(SessionData).delete()
            self.db.commit()
        except SQLAlchemyError as e:
            logger.error(f"Database error while removing session : {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected database error: {e}")