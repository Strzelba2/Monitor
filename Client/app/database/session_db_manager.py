from app.database import AsyncSessionLocal
from sqlalchemy.future import select
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.models import SessionData
from app.database.base import BaseManager, SingletonMeta
from datetime import datetime, timezone, timedelta
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from app.exceptions.database_exc import SessionDBManagerError
from typing import Optional, List
from config.config import Config
from cryptography.fernet import InvalidToken
import logging

logger = logging.getLogger(__name__)

class SessionDBManager(BaseManager, metaclass=SingletonMeta):
    """
    Manages session data in the database, including creation, updating, 
    validation, retrieval, and listing of sessions.
    """
    def __init__(self,session_factory=None):
        """
        Initializes the SessionManager with a database session.
        """
        # super().__init__()
        self.session_factory = session_factory or AsyncSessionLocal
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
        
    async def __create_session(self, session_id: str, created: datetime, expired: datetime, session: AsyncSession) -> None:
        """
        Creates a new session in the database.

        Args:
            session_id (str): The unique identifier for the session.
            created (datetime): The session creation timestamp.
            expired (datetime): The session expiration timestamp.
            session(AsyncSession): Aysync local Session.

        Raises:
            IntegrityError: If a session with the same ID already exists.
            SQLAlchemyError: For any database-related issues.
        """
        logger.info(f"Attempting to create a new session ")

        session_data = SessionData(
            session_id=self.encrypt(session_id),
            created_at=created,
            expires_at=expired)
        try:
            session.add(session_data)

            logger.info(f"Session with ID {session_id} created successfully.")
        except IntegrityError as e:
            logger.error(f"Integrity error while creating session with ID {session_id}: {e}")
            raise
        except SQLAlchemyError as e:
            logger.critical(f"Unexpected database error: {e}")
            raise
        except InvalidToken as e:
            logger.error(f"Failed to encrypt session : {e}")
            raise 
        except Exception as e:
            logger.exception(f"Unknown error while creating session: {e}")
            raise
        
    async def update_session(self, session_id: str, created: datetime, expired: datetime) -> None:
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
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    self.validate_session(created, expired)
                    current_session = await self._get_session(session)
                    if current_session:
                        logger.info("session exist...")
                        if current_session.session_id == session_id:
                            logger.info("The session ID is already up to date.")
                            return
                        logger.debug(f"Updating session ID ....")
                        current_session.session_id = self.encrypt(session_id)
                        current_session.created_at = created
                        current_session.expires_at = expired
                        logger.debug(f"Session ID updated to ....")
                    else:
                        logger.debug(f"No existing session found. Creating a new session with ID.")
                        await self.__create_session(session_id,created, expired, session)

            except SQLAlchemyError as e:
                logger.error(f"Database error while updating session with ID: {e}")
                raise SessionDBManagerError(str(e))
            except InvalidToken as e:
                logger.error(f"Failed to decrypt or encrypt session : {e}")
                raise 
            except Exception as e:
                logger.exception(f"Unknown error while updating session: {e}")
                raise
        
    async def _get_session(self, session: AsyncSession) -> Optional[SessionData]: 
        """
        Retrieves the first session from the database.
        
        Args:
            session(AsyncSession): Aysync local Session.

        Returns:
            Optional[SessionData]: The first session found or None if no session exists.

        """ 
        stmt = (
            select(SessionData)
            .execution_options(populate_existing=True) 
        )
        result = await session.execute(stmt)
        current_session = result.scalar_one_or_none()
        return current_session
             
    async def get_session(self) -> Optional[SessionData]:
        """
        Retrieves the first session from the database.

        Returns:
            Optional[SessionData]: The first session found or None if no session exists.

        Raises:
            SQLAlchemyError: For any database-related issues.
        """
        logger.info("Retrieving the first session from the database.")
        now = datetime.now(timezone.utc)
        async with self.session_factory() as session:
            async with session.begin():
                try:
                    curremt_session = await self._get_session(session)
                    if curremt_session:
                        logger.info(f"Session found")
                        logger.info(f"{curremt_session.expires_at.tzinfo}")
                        if curremt_session.expires_at <= now:
                            try:
                                await self._clear_sessions(session)
                                logger.info(f"Session  was deleted successfully.")
                                return None
                            except Exception : 
                                logger.error(f"Failed to delete session :")
                        logger.debug(f"session:{curremt_session.session_id}")     
                        curremt_session.session_id = self.decrypt(curremt_session.session_id)
                            
                    else:
                        logger.info("No session found.")
                    return curremt_session
                except SQLAlchemyError as e:
                    logger.error(f"Database error while retrieving the first session: {e}")
                    raise
                except InvalidToken as e:
                    logger.error(f"Failed to decrypt session : {e}")
                    raise 
                except Exception as e:
                    logger.exception(f"Unknown error while retrieving the first session: {e}")
                    raise
    
    async def list_all_sessions(self) -> List[SessionData]:
        """
        Retrieves all sessions from the database.

        Returns:
            List[SessionData]: A list of all session objects.
        """
        logger.info("Retrieving all sessions from the database.")
        async with self.session_factory() as session:
            try:
                sessions_result = await session.execute(select(SessionData))
                sessions = sessions_result.scalars().all()
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
        
    async def _clear_sessions(self, session: AsyncSession) -> None:
        """
        Clears all session data from the database.

        This method attempts to delete all entries in the `SessionData` table. 
        
        Args:
            session(AsyncSession): Aysync local Session.
        
        """ 
        stmt = delete(SessionData)
        await session.execute(stmt)
        logger.info(f"All sessions deleted successfully.")
        
    async def clear_sessions(self)-> Optional[List]:
        """
        Clears all session data from the database.

        This method attempts to delete all entries in the `SessionData` table. 
        
        Returns:
            Optional[List]: An empty list if the operation fails
        """
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    await self._clear_sessions(session)
            except SQLAlchemyError as e:
                logger.error(f"Database error while removing session : {e}")
                return []
            except Exception as e:
                logger.error(f"Unexpected database error: {e}")