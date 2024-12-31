from app.database import AsyncSessionLocal
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete
from app.database.models import UserSettings
from sqlalchemy.exc import  SQLAlchemyError,OperationalError, InterfaceError
from app.exceptions.database_exc import SettingsDBManagerError,CriticalDatabaseError
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

class SettingsMeta(type):
    """
    Metaclass for managing singleton instances of classes.
    Ensures only one instance of a class using this metaclass is created.
    """
    _instances = {}
    
    async def __call__(cls, *args, **kwargs):
        """
        Creates or retrieves the singleton instance of the class.

        Args:
            args: Positional arguments for the class constructor.
            
        Kwargs:
            kwargs: Keyword arguments for the class constructor.
            
        Return:
            : The singleton instance of the class.
        """
        if cls not in cls._instances:
            try:
                logger.info(f"Creating a new instance of {cls.__name__}")
                cls._instances[cls] = super().__call__(*args, **kwargs)
                await cls._instances[cls].init_settings_manager()
            except SettingsDBManagerError as e:
                logger.error(f"Failed to initialize settings manager: {e}")
                raise
            except CriticalDatabaseError as e:
                logger.error(f"Critical error during singleton initializationr: {e}")
                raise
            except Exception as e:
                logger.exception("Unknown error while initiation settiings data")
                raise
        else:
            logger.debug(f"Reusing existing instance of {cls.__name__}")
        return cls._instances[cls]

class SettingsDBManager(metaclass=SettingsMeta):
    """
    Manages user settings stored in a database.
    Provides methods to retrieve, update, and reset settings like username and remember_me status.
    """
    def __init__(self, session_factory=None):
        """
        Initializes the SettingsManager with a database session.
        """
        self.session_factory = session_factory or AsyncSessionLocal
        self._username: Optional[str] = None
        self._remember_me: Optional[bool] = None
        logger.info("SettingsManager initialized with a database session.")
        
    @property
    def username(self) -> Optional[str]:
        """
        Retrieves the stored username.

        Return:
            Optional[strThe username or None if not set.
        """
        logger.debug(f"Accessing username: {self._username}")
        return self._username
    
    @property
    def remember_me(self) -> Optional[bool]:
        """
        Retrieves the 'remember_me' flag.

        Resturn:
            Optional[bool]The value of 'remember_me' or None if not set.
        """
        logger.debug(f"Accessing remember_me: {self._remember_me}")
        return self._remember_me
 
    async def init_settings_manager(self) -> None:
        """
        Initializes the settings manager by loading the user's settings from the database.
        """
        try:
            setting = await self.get_user_setting() 
            logger.debug(f"init_settings_manager  setting: {setting}")
            if setting:
                logger.debug(f"Found existing settings: {setting}")
                if setting.remember_me and setting.username:
                    self._remember_me = setting.remember_me
                    self._username = setting.username
                else:
                    await self.reset_remember_me()
            else:
                logger.debug("No settings found, setting 'remember_me' to False.")
                self._remember_me = False
        except OperationalError as e:
            logger.error(f"Database connection failed: {e}")
            raise CriticalDatabaseError("Database connection failed.")
        except InterfaceError as e:
            logger.error(f"Database interface error: {e}")
            raise CriticalDatabaseError("Database driver error.")
        except SQLAlchemyError as e:
            logger.error(f"Database error during settings initialization: {e}")
            raise SettingsDBManagerError("Database error during settings initialization.")
        except Exception as e:
            logger.exception(f"Unknown error while initiation settiings data {e}")
            raise

    async def set_remember_me(self, remember: bool, username: Optional[str] = None) -> None:
        """
        Updates the 'remember_me' flag and username in the database.

        Args:
            remember(bool): Boolean value for 'remember_me'.
            username(Optional[str]): The username to set.
        Raises:
            ValueError: If username is not provided.
            SettingsDBManagerError: If a database or unknown error occurs.
        """
        async with self.session_factory() as session:
            try:
                if not username:
                    raise ValueError("Username must be provided.")
                
                if not remember:
                    raise ValueError("remeber must be True.")
                
                logger.debug(f"Updating 'remember_me' to {remember} for username '{username}'")
                async with session.begin():

                    setting = await self._get_user_setting(session)

                    if setting:
                        setting.remember_me = remember
                        setting.username = username
                    else:
                        setting = UserSettings(username=username, remember_me=remember)
                        session.add(setting)
                
                self._remember_me = remember
                self._username = username
                logger.info(f"Settings updated successfully: remember_me={remember}, username={username}")
                
            except SQLAlchemyError as e:
                logger.error(f"Database error while updating settings: {e}")
                raise SettingsDBManagerError(f"Database error while updating settings: {e}")
            except ValueError as e:
                raise
            except Exception as e:
                logger.exception(f"Unknown error while updating settings: {e}")
                raise SettingsDBManagerError(f"Unknown error while updating settings: {e}")
            
    async def _get_user_setting(self,session: AsyncSession) -> Optional[UserSettings]:
        """
        Retrieves the user's settings from the database.
        Return:
            Optional[UserSettings]: A UserSettings object or None if no settings are found.
        """
        try:
            stmt = select(UserSettings).execution_options(populate_existing=True)
            result = await session.execute(stmt)
            user_settings = result.scalar()
            logger.debug(f"Retrieved user settings: {user_settings}")
            return user_settings
        except Exception as e:
            logger.exception(f"Unknown error while session execution: {e}")
            raise e

    async def get_user_setting(self) :
        """
        Retrieves the user's settings from the database.
        Return:
            Optional[UserSettings]: A UserSettings object or None if no settings are found.
        """
        logger.info("Get user processing...")
        async with self.session_factory() as session:
            try:
                user_settings = await self._get_user_setting(session)
                logger.info(f"Get user processing succefully: {user_settings}")
                return user_settings
            except SQLAlchemyError as e:
                logger.error(f"Database error while retrieving the settings: {str(e)}")
                raise 
            except Exception as e:
                logger.exception(f"Unknown error while retrieving the settings: {str(e)}")
                raise 

    async def reset_remember_me(self) -> None:
        """
        Resets the 'remember_me' and 'username' settings to their default values.

        This method retrieves the user's settings and updates the `remember_me` flag to `False` 
        and sets the `username` to `None`. If no settings are found, it creates a new default entry. 
        The method ensures changes are committed to the database and updates the internal state variables.

        Args:
            None

        Returns:
            None
        """
        async with self.session_factory() as session:
            try:
                logger.debug("Resetting 'remember_me' and username to default values.")
                async with session.begin():
                    setting = await self._get_user_setting(session)
                    if setting:
                        logger.debug(f"Existing user settings {setting} found. Updating values.")
                        setting.remember_me = False
                        setting.username = None
                    else:
                        logger.debug("No user settings found. Creating default settings.")
                        setting = UserSettings(username=None, remember_me=False)
                        session.add(setting)

                self._remember_me = False
                self._username = None
                    
                logger.info("Successfully reset 'remember_me' and username.")
                    
            except SQLAlchemyError as e:
                logger.error(f"Database error while reseting the settings: {e}")
                raise
            except Exception as e:
                logger.exception(f"Unknown error while reseting the settings: {e}")
                raise
        
    async def list_all_settings(self) -> List[UserSettings]:
        """
        Retrieves all sessions from the database.

        Returns:
            List[UserSettings]: A list of all settings objects.
        """
        logger.info("Retrieving all settings from the database.")
        async with self.session_factory() as session:
            try:
                result = await session.execute(select(UserSettings))
                settings = result.scalars().all()
                for setting in settings:
                    logger.info(f"setting: {setting.username}")
                logger.info(f"Retrieved {len(settings)} settings from the database.")
                return settings
            except SQLAlchemyError as e:
                logger.error(f"Database error while retrieving setting list: {e}")
                raise
            except Exception as e:
                logger.error(f"Error retrieving setting list: {e}")
                raise
        
    async def clean_settings(self)-> None:
        """
        Deletes all user settings from the database.

        Raises:
            SQLAlchemyError: If there is an error with the database operation during deletion.
            Exception: If there is an unexpected error during the deletion process.
        """
        async with self.session_factory() as session:
            try:
                logger.info("Attempting to delete all user settings from the database.")
                async with session.begin():
                    stmt = delete(UserSettings)
                    await session.execute(stmt)
                logger.info("Successfully deleted all user settings from the database.")
            except SQLAlchemyError as e:
                logger.error(f"Database error while removing settings : {e}")
                return []
            except Exception as e:
                logger.error(f"Unexpected database error: {e}")
            
