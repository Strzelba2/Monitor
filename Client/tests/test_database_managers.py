import unittest
import asyncio
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.future import select
from app.database import Base
from unittest.mock import MagicMock, patch, AsyncMock
from app.database.models import SessionData,RefreshTokenData,TokenData, UserSettings
from app.database.session_db_manager import SessionDBManager
from app.database.token_db_manager import TokenDManager
from app.database.settings_db_manager import SettingsDBManager
from sqlalchemy.exc import IntegrityError,SQLAlchemyError, OperationalError, InterfaceError
from app.exceptions.database_exc import SessionDBManagerError, TokenDBManagerError,SettingsDBManagerError,CriticalDatabaseError
from datetime import datetime, timedelta, timezone
from config.config import Config
import logging

logger = logging.getLogger(__name__)

class TestSessionManager(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Create a new session for each test."""
        logger.info("TestSessionManager asyncSetUp")
        self.test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        self.TestSessionLocal = sessionmaker(class_=AsyncSession, expire_on_commit=False,autocommit=False, autoflush=False, bind=self.test_engine)
        async with self.test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.session_manager = SessionDBManager(session_factory=self.TestSessionLocal)

        self.session_manager.generate_secret_key("939111", "fakepasword")
        await self.session_manager.clear_sessions()
        logger.info("TestSessionManager asyncSetUp successfully")

    async def asyncTearDown(self):
        """Rollback any changes and close the session."""
        logger.info("asyncTearDown")
        SessionDBManager._instances.clear()
        async with self.test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.test_engine.dispose()
        
    async def test_shared_cipher(self):
        """Test if cipher can by init once"""
        token_manager = TokenDManager(session_factory=self.TestSessionLocal)

        self.assertIsNotNone(self.session_manager.cipher)
        self.assertIsNotNone(token_manager.cipher)
        
    async def test_create_session_success(self):
        """Test successful creation of a session."""
        logger.info("Started: test_create_session_success")
        
        session_id = "test_session_id"
        now = datetime.now(timezone.utc)
        expired = now + timedelta(hours=2)
        await self.session_manager.update_session(session_id,expired)

        session = await self.session_manager.get_session()
        self.assertEqual(session.session_id, session_id)
        
        logger.info("Test Passed: test_create_session_success")

    async def test_create_session_double_try(self):
        """Test session creation with double try"""
        logger.info("Test Started: test_create_session_double_try")
        session_id = "test_session_id"
        now = datetime.now(timezone.utc)
        expired = now + timedelta(hours=2)
        await self.session_manager.update_session(session_id,expired)

        await self.session_manager.update_session(session_id,expired)
        
        session = await self.session_manager.get_session()
        self.assertEqual(session.session_id, session_id)
        
        logger.info("Test Passed: test_create_session_double_try")
        
    async def test_create_session_error(self):
        """Test of __create_session call"""
        
        logger.info("Test Started: test_create_session_error")
        
        session_id = "test_session_id"
        with self.assertRaises(AttributeError):
            await self.session_manager.__create_session(session_id)
            
        logger.info("Test Passed: test_create_session_error")

    async def test_update_session_existing(self):
        """Test updating an existing session."""
        logger.info("Test Started: test_update_session_existing")

        session_data = SessionData(session_id=self.session_manager.encrypt("existing_session"))
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(session_data)

        await self.session_manager.update_session("existing_session",session_data.expires_at)
        
        current_session = await self.session_manager.get_session()

        self.assertEqual("existing_session", current_session.session_id)
        
        logger.info("Test Passed: test_update_session_existing")
        
    async def test_update_session_integrityError(self):
        """Test update session with IntegrityError"""
        logger.info("Test Started: test_update_session_integrityError")
        
        mock_session = MagicMock()
        
        # Raise an IntegrityError
        mock_session.execute = AsyncMock(side_effect=IntegrityError("Test IntegrityError", params="TestParams", orig=None))
        
        # Replace session factory in your settings manager with the mock
        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        # mock_session_factory.__aexit__ = AsyncMock()
        self.session_manager.session_factory = MagicMock(return_value=mock_session_factory)

        session_id = "test_session_id_new"
        now = datetime.now(timezone.utc)
        expired = now + timedelta(hours=2)
        with self.assertRaises(SessionDBManagerError):
            await self.session_manager.update_session(session_id, expired)
        
        logger.info("Test Passed: test_update_session_integrityError")

    
    async def test_get_session_none(self):
        """Test if get_session method returns the correct session none."""
        
        logger.info("Test Started: test_get_session_none")

        session = await self.session_manager.get_session()

        # Assert that the session is not None and the session_id is correct
        self.assertIsNone(session)
        
        logger.info("Test Passed: test_get_session_none")
    
    async def test_get_session_sqlalchemy_error(self):
        """Test if get_session handles SQLAlchemyError."""
        logger.info("Test Started: test_get_session_sqlalchemy_error")
        # Create a mock for the session manager's db query method
        
        mock_session = MagicMock()
        
        # Raise an SQLAlchemyError
        mock_session.execute = AsyncMock(side_effect=SQLAlchemyError("SQLAlchemy error occurred"))
        
        # Replace session factory in your settings manager with the mock
        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        # mock_session_factory.__aexit__ = AsyncMock()
        self.session_manager.session_factory = MagicMock(return_value=mock_session_factory)

        # Call the get_session method
        with self.assertRaises(SQLAlchemyError):
            await self.session_manager.get_session()
            
        logger.info("Test Passed: test_get_session_sqlalchemy_error")
            
    async def test_get_session_operational_error(self):
        """Test if get_session handles OperationalError."""
        logger.info("Test Started: test_get_session_operational_error")
        # Create a mock for the session manager's db query method
        
        mock_session = MagicMock()
        
        # Raise an OperationalError 
        mock_session.execute = AsyncMock(side_effect=OperationalError("Database connection error", "params", "orig"))
        
        # Replace session factory in your settings manager with the mock
        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        # mock_session_factory.__aexit__ = AsyncMock()
        self.session_manager.session_factory = MagicMock(return_value=mock_session_factory)

        # Call the get_session method
        with self.assertRaises(SQLAlchemyError):
            await self.session_manager.get_session()
            
        logger.info("Test Passed: test_get_session_operational_error")
            
    async def test_get_session_integrity_error(self):
        """Test if get_session handles IntegrityError."""
        logger.info("Test Started: test_get_session_integrity_error")
        # Create a mock for the session manager's db query method
        
        mock_session = MagicMock()
        
        # Raise an SQLAlchemyError
        mock_session.execute = AsyncMock(side_effect=IntegrityError("Integrity error occurred", "params", "orig"))
        
        # Replace session factory in your settings manager with the mock
        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        # mock_session_factory.__aexit__ = AsyncMock()
        self.session_manager.session_factory = MagicMock(return_value=mock_session_factory)

        # Call the get_session method
        with self.assertRaises(SQLAlchemyError):
            await self.session_manager.get_session()
            
        logger.info("Test Passed: test_get_session_integrity_error")
            
    async def test_get_session_timeout_error(self):
        """Test if get_session handles TimeoutError."""
        logger.info("Test Started: test_get_session_timeout_error")
        # Create a mock for the session manager's db query method
        
        mock_session = MagicMock()
        
        # Raise an SQLAlchemyError
        mock_session.execute = AsyncMock(side_effect=TimeoutError("Query timeout occurred"))
        
        # Replace session factory in your settings manager with the mock
        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        # mock_session_factory.__aexit__ = AsyncMock()
        self.session_manager.session_factory = MagicMock(return_value=mock_session_factory)

        # Call the get_session method
        with self.assertRaises(Exception):
            await self.session_manager.get_session()
            
        logger.info("Test Passed: test_get_session_timeout_error")

    async def test_list_all_sessions(self):
        """Test listing all sessions."""
        logger.info("Test Started: test_list_all_sessions")
        mock_sessions = [
            SessionData(session_id=self.session_manager.encrypt("session1")),
            SessionData(session_id=self.session_manager.encrypt("session2")),
        ]
        async with self.TestSessionLocal() as session:
            async with session.begin():
                for session_data in mock_sessions:
                    session.add(session_data)

        sessions = await self.session_manager.list_all_sessions()

        self.assertEqual(len(sessions), 2)
        self.assertEqual(sessions[0].session_id, "session1")
        self.assertEqual(sessions[1].session_id, "session2")
        
        logger.info("Test Passed: test_list_all_sessions")
        
    async def test_timezone_awareness_after_creation(self):
        """Test if expired is time aware"""
        logger.info("Test Started: test_timezone_awareness_after_creation")
        session_id = "test_session_id"
        now = datetime.now(timezone.utc)
        expired = now + timedelta(hours=2)

        await self.session_manager.update_session(session_id, expired)

        session = await self.session_manager.get_session()
        self.assertIsNotNone(session.expires_at.tzinfo)
        self.assertEqual(session.expires_at.tzinfo.utcoffset(session.expires_at) , timedelta(0))
        
        logger.info("Test Passed: test_timezone_awareness_after_creation")
        
    async def test_validate_session(self):
        """Test session expired time validation"""
        logger.info("Test Started: test_validate_session")
        
        session_id = "test_session_id"
        now = datetime.now(timezone.utc)
        expired = now - timedelta(hours=2)
        
        with self.assertRaises(ValueError):
            await self.session_manager.update_session(session_id,expired)

        session = await self.session_manager.get_session()
        self.assertIsNone(session)

        expired = now + timedelta(hours=3)
        
        with self.assertRaises(ValueError):
            await self.session_manager.update_session(session_id,expired)

        session = await self.session_manager.get_session()
        self.assertIsNone(session)
        
        logger.info("Test Passed: test_validate_session")
        
    async def test_get_session_deletes_expired(self):
        """Test deletion of an overdone session """
        logger.info("Test Started: test_get_session_deletes_expired")
        
        sessions_before = await self.session_manager.list_all_sessions()
        self.assertEqual(len(sessions_before), 0)
        
        encrypted_session = self.session_manager.encrypt("expired_session")
        now = datetime.now(timezone.utc)
        expired_session = SessionData(
            session_id= encrypted_session,
            expires_at=now - timedelta(minutes=1),
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(expired_session)

        sessions_before = await self.session_manager.list_all_sessions()
        self.assertEqual(len(sessions_before), 1)
        self.assertEqual(sessions_before[0].session_id, "expired_session")

        session = await self.session_manager.get_session()
        
        sessions_after = await self.session_manager.list_all_sessions()
        self.assertEqual(len(sessions_after), 0)
        
        self.assertIsNone(session)
        
        logger.info("Test Passed: test_get_session_deletes_expired")
        
class TestTokenManager(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        """Create a new session for each test."""
        logger.info("TestTokenManager asyncSetUp")
        self.test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        self.TestSessionLocal = sessionmaker(class_=AsyncSession, expire_on_commit=False,autocommit=False, autoflush=False, bind=self.test_engine)
        async with self.test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.token_manager = TokenDManager(session_factory=self.TestSessionLocal)

        self.token_manager.generate_secret_key("939111", "fakepasword")
        await self.token_manager.clear_token('access')
        await self.token_manager.clear_token('refresh')
        logger.info("TestTokenManager asyncSetUp successfully")

    async def asyncTearDown(self):
        """Rollback any changes and close the session."""
        logger.info("asyncTearDown")
        TokenDManager._instances.clear()
        async with self.test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.test_engine.dispose()

    async def test_validate_tokens_success(self):
        """Test successful validation of valid tokens."""
        logger.info("Started: test_validate_tokens_success")
        access_token = TokenData(
            token="valid_access_token",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        refresh_token = RefreshTokenData(
            token="valid_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(access_token)
                session.add(refresh_token)


        result = self.token_manager.validate_tokens(access_token, refresh_token)
        self.assertTrue(result)
        logger.info("Test passed: test_validate_tokens_success")
        
        
    async def test_validate_tokens_invalid_expiry(self):
        """Test validation failure for expired tokens."""
        logger.info("Test Started: test_validate_tokens_invalid_expiry")
        access_token = TokenData(
            token="expired_access_token",
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        refresh_token = RefreshTokenData(
            token="valid_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(access_token)
                session.add(refresh_token)


        with self.assertRaises(ValueError):
            self.token_manager.validate_tokens(access_token, refresh_token)
            
        logger.info("Test Passed: test_validate_tokens_invalid_expiry")
            
    async def test_validate_tokens_invalid_expiry_expired(self):
        """Test validation failure for expired tokens."""
        logger.info("Test Started: test_validate_tokens_invalid_expiry_expired")
        access_token = TokenData(
            token="expired_access_token",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)+ timedelta(minutes=int(Config.TOKEN_EXPIRATION_MINUTES)),
        )
        refresh_token = RefreshTokenData(
            token="valid_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(access_token)
                session.add(refresh_token)

        with self.assertRaises(ValueError):
            self.token_manager.validate_tokens(access_token, refresh_token)
            
        logger.info("Test Passed: test_validate_tokens_invalid_expiry_expired")
            
    async def test_get_valid_token_success(self):
        """Test retrieval of a valid token."""
        logger.info("Test Started: test_get_valid_token_success")
        token = TokenData(
            token=self.token_manager.encrypt("valid_access_token"),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(token)

        result = await self.token_manager.get_valid_token("access")
        self.assertIsNotNone(result)
        self.assertEqual(result.token, "valid_access_token")
        
        self.assertIsNotNone(result.expires_at.tzinfo)
        self.assertEqual(result.expires_at.tzinfo.utcoffset(result.expires_at) , timedelta(0))
        
        logger.info("Test Passed: test_get_valid_token_success")
        
    async def test_get_valid_refresh_token_success(self):
        """Test retrieval of a valid refresh token."""
        logger.info("Test Started: test_get_valid_refresh_token_success")
        token = RefreshTokenData(
            token=self.token_manager.encrypt("valid_refresh_token"),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(token)

        result = await self.token_manager.get_valid_token("refresh")
        self.assertIsNotNone(result)
        self.assertEqual(result.token, "valid_refresh_token")
        
        self.assertIsNotNone(result.expires_at.tzinfo)
        self.assertEqual(result.expires_at.tzinfo.utcoffset(result.expires_at) , timedelta(0))
        
        logger.info("Test Passed: test_get_valid_refresh_token_success")

    async def test_get_valid_token_none(self):
        """Test retrieval of a valid token when no valid tokens exist."""
        logger.info("Test Started: test_get_valid_token_none")
        result = await self.token_manager.get_valid_token("access")
        self.assertIsNone(result)
        
        logger.info("Test Passed: test_get_valid_token_none")
        
    async def test_create_token_success(self):
        """Test creating a new access and refresh token."""
        logger.info("Test Started: test_create_token_success")
        access_token = TokenData(
            token="new_access_token",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        refresh_token = RefreshTokenData(
            token="new_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                await self.token_manager._TokenDManager__create_token(access_token, refresh_token,session)
                
        async with self.TestSessionLocal() as session:

            tokens_result = await session.execute(select(TokenData))
            tokens = tokens_result.scalars().all()
            
            self.assertEqual(len(tokens), 1)
            self.assertNotEqual(tokens[0].token, "new_access_token")
        
            tokens_result = await session.execute(select(RefreshTokenData))
            tokens = tokens_result.scalars().all()
            self.assertEqual(len(tokens), 1)
            self.assertNotEqual(tokens[0].token, "new_refresh_token")
        
        logger.info("Test Passed: test_create_token_success")
        
    async def test_clear_token(self):
        """Test cleaning tokens of a specific type."""
        logger.info("Test Started: test_clear_token")
        token = TokenData(
            token="to_be_deleted",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(token)

        await self.token_manager.clear_token("access")
        
        async with self.TestSessionLocal() as session:
            tokens_result = await session.execute(select(TokenData))
            tokens = tokens_result.scalars().all()
            
        self.assertEqual(len(tokens), 0)
        
        logger.info("Test Passed: test_clear_token")
        
    async def test_get_all_tokens(self):
        """Test retrieving all tokens."""
        logger.info("Test Started: test_get_all_tokens")
        access_token = TokenData(
            token=self.token_manager.encrypt("access1"), expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
        )
        refresh_token = RefreshTokenData(
            token=self.token_manager.encrypt("refresh1"), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(access_token)
                session.add(refresh_token)

        tokens = await self.token_manager.get_all_tokens()
        self.assertIn("access_tokens", tokens)
        self.assertIn("refresh_tokens", tokens)
        self.assertEqual(len(tokens["access_tokens"]), 1)
        self.assertEqual(len(tokens["refresh_tokens"]), 1)
        
        logger.info("Test Passed: test_get_all_tokens")
        
    async def test_update_tokens_success(self):
        """Test successfully updating existing tokens."""
        logger.info("Test Started: test_update_tokens_success")
        access_token = TokenData(
            token=self.token_manager.encrypt("old_access_token"), expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
        )
        refresh_token = RefreshTokenData(
            token=self.token_manager.encrypt("old_refresh_token"), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(access_token)
                session.add(refresh_token)

        new_access_token = TokenData(
            token="new_access_token", expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)
        )
        new_refresh_token = RefreshTokenData(
            token="new_refresh_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )
        
        await self.token_manager.update_tokens(new_access_token, new_refresh_token)

        async with self.TestSessionLocal() as session:

            tokens_result = await session.execute(select(TokenData))
            tokens = tokens_result.scalars().all()
            
            self.assertEqual(len(tokens), 1)
            self.assertNotEqual(tokens[0].token, "new_access_token")
        
            tokens_result = await session.execute(select(RefreshTokenData))
            tokens = tokens_result.scalars().all()
            
            self.assertEqual(len(tokens), 1)
            self.assertNotEqual(tokens[0].token, "new_refresh_token")
            
        access_token = await self.token_manager.get_valid_token("access")
        
        self.assertEqual(access_token.token, "new_access_token")

        logger.info("Test Passed: test_update_tokens_success")

    async def test_update_tokens_missing_tokens(self):
        """Test creating new tokens if existing tokens are missing."""
        logger.info("Test Started: test_update_tokens_missing_tokens")
        new_access_token = TokenData(
            token="new_access_token", expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)
        )
        new_refresh_token = RefreshTokenData(
            token="new_refresh_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )
        await self.token_manager.update_tokens(new_access_token, new_refresh_token)

        async with self.TestSessionLocal() as session:

            tokens_result = await session.execute(select(TokenData))
            tokens = tokens_result.scalars().all()
            
            self.assertEqual(len(tokens), 1)
        
            tokens_result = await session.execute(select(RefreshTokenData))
            tokens = tokens_result.scalars().all()
            
            self.assertEqual(len(tokens), 1)
        
        logger.info("Test Passed: test_update_tokens_missing_tokens")

    async def test_update_tokens_existing_tokens_already_updated(self):
        """Test no changes when tokens are already up-to-date."""
        logger.info("Test Started: test_update_tokens_existing_tokens_already_updated")
        access_token = TokenData(
            token=self.token_manager.encrypt("current_access_token"), expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)
        )
        refresh_token = RefreshTokenData(
            token=self.token_manager.encrypt("current_refresh_token"), expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(access_token)
                session.add(refresh_token)
        
        access_token.token = "current_access_token"
        refresh_token.token = "current_refresh_token"

        await self.token_manager.update_tokens(access_token, refresh_token)

        async with self.TestSessionLocal() as session:

            tokens_result = await session.execute(select(TokenData))
            tokens = tokens_result.scalars().all()
            
            self.assertEqual(len(tokens), 1)
        
            tokens_result = await session.execute(select(RefreshTokenData))
            tokens = tokens_result.scalars().all()
            
            self.assertEqual(len(tokens), 1)
            
        current_access_token = await self.token_manager.get_valid_token("access")
        
        self.assertEqual(access_token.token, current_access_token.token)
        
        logger.info("Test Passed: test_update_tokens_existing_tokens_already_updated")

    async def test_update_tokens_invalid_tokens(self):
        """Test validation failure when tokens are invalid."""
        logger.info("Test Started: test_update_tokens_invalid_tokens")
        new_access_token = TokenData(
            token="invalid_access_token", expires_at=datetime.now(timezone.utc) - timedelta(minutes=10)
        )
        new_refresh_token = RefreshTokenData(
            token="new_refresh_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )

        with self.assertRaises(ValueError):
            await self.token_manager.update_tokens(new_access_token, new_refresh_token)
            
        logger.info("Test Passed: test_update_tokens_invalid_tokens")

    async def test_update_tokens_database_error(self):
        """Test database error during token update."""
        logger.info("Test Started: test_update_tokens_database_error")
        new_access_token = TokenData(
            token="new_access_token", expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)
        )
        new_refresh_token = RefreshTokenData(
            token="new_refresh_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )

        mock_session = MagicMock()
        
        # Raise an IntegrityError when first() is called
        mock_session.execute = AsyncMock(side_effect=SQLAlchemyError("DB error"))
        
        # Replace session factory in your settings manager with the mock
        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        # mock_session_factory.__aexit__ = AsyncMock()
        self.token_manager.session_factory = MagicMock(return_value=mock_session_factory)
        # with patch.object(self.token_manager.session_factory, "commit", side_effect=SQLAlchemyError("DB error")):
        with self.assertRaises(TokenDBManagerError):
            await self.token_manager.update_tokens(new_access_token, new_refresh_token)
            
        self.token_manager.session_factory = self.TestSessionLocal
                
        logger.info("Test Passed: test_update_tokens_database_error")

    async def test_update_tokens_clean_old_tokens(self):
        """Test cleaning old tokens when missing new tokens."""
        
        logger.info("Test Started: test_update_tokens_clean_old_tokens")
        
        old_encrypted_access_token = self.token_manager.encrypt("old_access_token")
        old_access_token = TokenData(
            token=old_encrypted_access_token, expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
        )
        
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(old_access_token)

        new_access_token = TokenData(
            token="new_access_token", expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)
        )
        new_refresh_token = RefreshTokenData(
            token="new_refresh_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )
        await self.token_manager.update_tokens(new_access_token, new_refresh_token)

        async with self.TestSessionLocal() as session:

            tokens_result = await session.execute(select(TokenData))
            tokens = tokens_result.scalars().all()
            
            self.assertEqual(len(tokens), 1)
        
        token = await self.token_manager.get_valid_token("access")
        
        self.assertEqual(token.token,"new_access_token")
        
        logger.info("Test Passed: test_update_tokens_clean_old_tokens")
        
    async def test_get_valid_token_again(self):
        """Test retrieval of a valid token."""
        logger.info("Test Started: test_get_valid_token_again")
        token = TokenData(
            token=self.token_manager.encrypt("valid_access_token"),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(token)

        result = await self.token_manager.get_valid_token("access")

        self.assertIsNotNone(result)
        self.assertEqual(result.token, "valid_access_token")
        
        self.assertIsNotNone(result.expires_at.tzinfo)
        self.assertEqual(result.expires_at.tzinfo.utcoffset(result.expires_at) , timedelta(0))
        
        result = await self.token_manager.get_valid_token("access")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.token, "valid_access_token")
        
        logger.info("Test Passed: test_get_valid_token_again")
        
    async def test_get_all_tokens_again(self):
        """Test retrieving all tokens."""
        logger.info("Test Started: test_get_all_tokens")
        access_token = TokenData(
            token=self.token_manager.encrypt("access1"), expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
        )
        refresh_token = RefreshTokenData(
            token=self.token_manager.encrypt("refresh1"), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(access_token)
                session.add(refresh_token)

        tokens = await self.token_manager.get_all_tokens()
        self.assertIn("access_tokens", tokens)
        self.assertIn("refresh_tokens", tokens)
        self.assertEqual(len(tokens["access_tokens"]), 1)
        self.assertEqual(len(tokens["refresh_tokens"]), 1)
        
        tokens = await self.token_manager.get_all_tokens()
        self.assertIn("access_tokens", tokens)
        self.assertIn("refresh_tokens", tokens)
        self.assertEqual(len(tokens["access_tokens"]), 1)
        self.assertEqual(len(tokens["refresh_tokens"]), 1)
        
        logger.info("Test Passed: test_get_all_tokens")
        
class TestSettingsManager(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        """Create a new session for each test."""
        logger.info("asyncSetUp")
        self.test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        self.TestSessionLocal = sessionmaker(class_=AsyncSession, expire_on_commit=False,autocommit=False, autoflush=False, bind=self.test_engine)
        async with self.test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        self.settings_manager = await SettingsDBManager(session_factory=self.TestSessionLocal)
        await self.settings_manager.reset_remember_me()
        logger.info("setup successful")

    async def asyncTearDown(self):
        """Rollback any changes and close the session."""
        logger.info("asyncTearDown")
        await self.settings_manager.list_all_settings()
        SettingsDBManager._instances.clear()
        
        async with self.test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.test_engine.dispose()

    async def test_singleton_behavior(self):
        """Test that SettingsManager adheres to singleton behavior."""
        logger.info("Test Started: test_singleton_behavior")
        manager1 = await SettingsDBManager(session_factory=self.TestSessionLocal)
        manager2 = await SettingsDBManager(session_factory=self.TestSessionLocal)
        self.assertIs(manager1, manager2, "SettingsManager is not a singleton.")
        
        logger.info("Test Passed: test_singleton_behavior")
        
    async def test_initialization_with_existing_settings(self):
        """Test initialization when settings already exist in the database."""
        logger.info("Test Started: test_initialization_with_existing_settings")
        # Create initial settings
        async with self.TestSessionLocal() as session:
            async with session.begin():
                settings = await self.settings_manager._get_user_setting(session)
                settings.username = "testuser"
                settings.remember_me = True


        await self.settings_manager.init_settings_manager()

        self.assertEqual(self.settings_manager.username, "testuser")
        self.assertTrue(self.settings_manager.remember_me)
        
        logger.info("Test Passed: test_initialization_with_existing_settings")
        
    async def test_initialization_without_existing_settings(self):
        """Test initialization when no settings exist in the database."""
        logger.info("Started Test: test_initialization_without_existing_settings")
        await self.settings_manager.clean_settings()
        await self.settings_manager.init_settings_manager()

        self.assertIsNone(self.settings_manager.username)
        self.assertFalse(self.settings_manager.remember_me)
        
        logger.info("Test Passed: test_initialization_without_existing_settings")
        
    async def test_initialization_operational_error(self):
        """Test if initialization handles OperationalError."""
        logger.info("Test Started: test_initialization_operational_error")
        mock_session = AsyncMock()

        # Raise an IntegrityError when first() is called
        mock_session.execute = AsyncMock(side_effect=OperationalError("OperationalError occurred", "params", "orig"))
        
        # Replace session factory in your settings manager with the mock
        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        # mock_session_factory.__aexit__ = AsyncMock()
        self.settings_manager.session_factory = MagicMock(return_value=mock_session_factory)
        # Call the get_session method
        with self.assertRaises(CriticalDatabaseError):
            await self.settings_manager.init_settings_manager()
         
        self.settings_manager.session_factory =  self.TestSessionLocal 
        logger.info("Test Passed: test_initialization_operational_error")
            
    async def test_initialization_integrity_error(self):
        """Test if initialization handles IntegrityError."""
        logger.info("Test Started: test_initialization_integrity_error")
        mock_session = MagicMock()
        
        # Raise an IntegrityError when first() is called
        mock_session.execute = AsyncMock(side_effect=IntegrityError("OperationalError occurred", "params", "orig"))
        
        # Replace session factory in your settings manager with the mock
        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        # mock_session_factory.__aexit__ = AsyncMock()
        self.settings_manager.session_factory = MagicMock(return_value=mock_session_factory)

        # Call the get_session method
        with self.assertRaises(SettingsDBManagerError):
            await self.settings_manager.init_settings_manager()
         
        self.settings_manager.session_factory =  self.TestSessionLocal    
        logger.info("Test Passed: test_initialization_integrity_error")
            
    async def test_set_remember_me_success(self):
        """Test setting the remember_me flag and username."""
        logger.info("Test Started: test_set_remember_me_success")
        await self.settings_manager.set_remember_me(True, username="testuser")
        
        async with self.TestSessionLocal() as session:
            settings = await self.settings_manager._get_user_setting(session)

        self.assertEqual(settings.username, "testuser")
        self.assertTrue(settings.remember_me)
        
        logger.info("Test Passed: test_set_remember_me_success")

    async def test_set_remember_me_missing_username(self):
        """Test that setting remember_me without a username raises an error."""
        logger.info("Test Started: test_set_remember_me_missing_username")
        with self.assertRaises(ValueError):
            await self.settings_manager.set_remember_me(True)
        logger.info("Test Passed: test_set_remember_me_missing_username")
            
    async def test_set_remember_me_remeber_false(self):
        """Test setting the remember_me flag and username."""
        logger.info("Test Started: test_set_remember_me_remeber_false")
        with self.assertRaises(ValueError):
            await self.settings_manager.set_remember_me(False, username="testuser")
            
        logger.info("Test Passed: test_set_remember_me_remeber_false")
            
    async def test_set_remember_me_in_empty_data(self):
        """Test setting the remember_me flag and username."""
        logger.info("Test Started: test_set_remember_me_in_empty_data")
        await self.settings_manager.clean_settings()
        await self.settings_manager.set_remember_me(True, username="testuser")

        async with self.TestSessionLocal() as session:
            settings = await self.settings_manager._get_user_setting(session)
            
        self.assertEqual(settings.username, "testuser")
        self.assertTrue(settings.remember_me)
        
        logger.info("Test Passed: test_set_remember_me_in_empty_data")
        
    async def test_reset_remember_me(self):
        """Test resetting the remember_me flag and username."""
        logger.info("Test Started: test_reset_remember_me")
        # Create initial settings
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(UserSettings(username="testuser", remember_me=True))


        await self.settings_manager.reset_remember_me()

        async with self.TestSessionLocal() as session:
            settings = await self.settings_manager._get_user_setting(session)
            
        self.assertIsNone(settings.username)
        self.assertFalse(settings.remember_me)
        self.assertIsNone(self.settings_manager.username)
        self.assertFalse(self.settings_manager.remember_me)
        
        logger.info("Test Passed: test_reset_remember_me")
        
    async def test_reset_remember_me_no_exist_data(self):
        """Test resetting the remember_me flag and username."""
        logger.info("Test Started: test_reset_remember_me_no_exist_data")
        # Create initial settings
        await self.settings_manager.clean_settings()

        await self.settings_manager.reset_remember_me()

        async with self.TestSessionLocal() as session:
            settings = await self.settings_manager._get_user_setting(session)
        self.assertIsNone(settings.username)
        self.assertFalse(settings.remember_me)
        self.assertIsNone(self.settings_manager.username)
        self.assertFalse(self.settings_manager.remember_me)
        
        logger.info("Test Passed: test_reset_remember_me_no_exist_data")
        
    async def test_get_user_setting_no_data(self):
        """Test retrieving user settings when none exist in the database."""
        logger.info("Test Started: test_get_user_setting_no_data")
        await self.settings_manager.clean_settings()
        setting = await self.settings_manager.get_user_setting()
        self.assertIsNone(setting)
        
        logger.info("Test Passed: test_get_user_setting_no_data")
        
    async def test_get_user_setting(self):
        """Test retrieving user settings from the database."""
        logger.info("Test Started: test_get_user_setting")
        # Add user settings
        async with self.TestSessionLocal() as session:
            async with session.begin():
                settings = await self.settings_manager._get_user_setting(session)
                settings.remember_me = True
                settings.username = "testuser"


        setting = await self.settings_manager.get_user_setting()
        self.assertIsNotNone(setting)
        self.assertEqual(setting.username, "testuser")
        self.assertTrue(setting.remember_me)
        
        logger.info("Test Passed: test_get_user_setting")
        
    async def test_list_all_users_setting(self):
        """Test getting a list of users"""
        logger.info("Test Started: test_list_all_users_setting")
        
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(UserSettings(username="testuser", remember_me=True))
        
        list_users = await self.settings_manager.list_all_settings()
        
        self.assertEqual(len(list_users),2)
        
        logger.info("Test Passed: test_list_all_users_setting")
        
    async def test_clean_data_user(self):
        """Test the deletion of all users"""
        logger.info("Test Started: test_clean_data_user")
        
        async with self.TestSessionLocal() as session:
            async with session.begin():
                session.add(UserSettings(username="testuser", remember_me=True))
        
        await self.settings_manager.clean_settings()
        
        list_users = await self.settings_manager.list_all_settings()
        
        self.assertEqual(len(list_users),0)
        
        logger.info("Test Passed: test_clean_data_user")
        


        
        
 

