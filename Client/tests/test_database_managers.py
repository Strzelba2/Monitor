import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from unittest.mock import MagicMock, patch
from app.database.models import SessionData,RefreshTokenData,TokenData, UserSettings
from app.database.session_manager import SessionManager
from app.database.token_manager import TokenManager
from app.database.settings_manager import SettingsManager
from sqlalchemy.exc import IntegrityError,SQLAlchemyError, OperationalError, InterfaceError
from app.exceptions.database_exc import SessionManagerError, TokenManagerError,SettingsManagerError,CriticalDatabaseError
from datetime import datetime, timedelta, timezone
from config.config import Config
import logging

logger = logging.getLogger(__name__)

class TestSessionManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up an in-memory SQLite database for testing."""
        # Create an in-memory SQLite engine for tests
        cls.test_engine = create_engine("sqlite:///:memory:", echo=False)
        cls.TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.test_engine)
        # Create the database schema
        Base.metadata.create_all(bind=cls.test_engine)
        
    @classmethod
    def tearDownClass(cls):
        """Drop all tables."""
        Base.metadata.drop_all(bind=cls.test_engine)

    def setUp(self):
        """Create a new session for each test."""
        # Start a new session
        self.db = self.TestSessionLocal()
        self.session_manager = SessionManager()
        self.session_manager.generate_secret_key("939111", "fakepasword")
        self.session_manager.db = self.db 
        # Start a new transaction to isolate tests
        self.session_manager.clean_sessions()
        self.db.begin()

    def tearDown(self):
        """Rollback any changes and close the session."""
        # Rollback any changes to ensure the database is clean for the next test
        self.db.rollback()
        
        # Close the session
        self.db.close()

    def test_create_session_success(self):
        """Test successful creation of a session."""
        
        logger.info("Started: test_create_session_success")
        
        session_id = "test_session_id"
        now = datetime.now(timezone.utc)
        expired = now + timedelta(hours=2)
        self.session_manager.update_session(session_id,now,expired)

        session = self.session_manager.get_session()
        self.assertEqual(session.session_id, session_id)
        
        logger.info("Test Passed: test_create_session_success")

    def test_create_session_double_try(self):
        """Test session creation with double try"""
        logger.info("Test Started: test_create_session_double_try")
        session_id = "test_session_id"
        now = datetime.now(timezone.utc)
        expired = now + timedelta(hours=2)
        self.session_manager.update_session(session_id,now,expired)

        self.session_manager.update_session(session_id,now,expired)
        
        session = self.session_manager.get_session()
        self.assertEqual(session.session_id, session_id)
        
        logger.info("Test Passed: test_create_session_double_try")
        
    def test_create_session_error(self):
        """Test of __create_session call"""
        
        logger.info("Test Started: test_create_session_error")
        
        session_id = "test_session_id"
        with self.assertRaises(AttributeError):
            self.session_manager.__create_session(session_id)
            
        logger.info("Test Passed: test_create_session_error")

    @patch("app.database.session_manager.SessionManager.get_session")
    def test_update_session_existing(self, mock_get_session):
        """Test updating an existing session."""
        logger.info("Test Started: test_update_session_existing")

        mock_session = SessionData(session_id="existing_session")
        mock_get_session.return_value = mock_session

        self.session_manager.update_session("existing_session",mock_session.created_at,mock_session.expires_at)

        self.assertEqual(mock_session.session_id, "existing_session")
        
        logger.info("Test Passed: test_update_session_existing")
        
    def test_update_session_rollback_called(self):
        """Test update session with SQLAlchemyError"""
        logger.info("Test Started: test_update_session_rollback_called")
        self.session_manager.db.commit = MagicMock(side_effect=SQLAlchemyError("Test SQLAlchemyError"))
        self.session_manager.db.rollback = MagicMock()

        session_id = "test_session_id_new"
        now = datetime.now(timezone.utc)
        expired = now + timedelta(hours=2)
        with self.assertRaises(SessionManagerError):
            self.session_manager.update_session(session_id,now,expired)

        # Assert rollback was called
        self.assertEqual(self.session_manager.db.rollback.call_count, 2)
        
        logger.info("Test Passed: test_update_session_rollback_called")
        
    def test_update_session_integrityError(self):
        """Test update session with IntegrityError"""
        logger.info("Test Started: test_update_session_integrityError")
      
        self.session_manager.db.commit = MagicMock(side_effect=IntegrityError("Test IntegrityError", params="TestParams", orig=None))
        self.session_manager.db.rollback = MagicMock()

        session_id = "test_session_id_new"
        now = datetime.now(timezone.utc)
        expired = now + timedelta(hours=2)
        with self.assertRaises(SessionManagerError):
            self.session_manager.update_session(session_id, now, expired)

        # Assert rollback was called
        self.assertEqual(self.session_manager.db.rollback.call_count, 2)
        
        logger.info("Test Passed: test_update_session_integrityError")

    @patch("app.database.session_manager.SessionManager.get_session")
    def test_update_session_new(self, mock_get_session):
        """Test creating a new session when none exists."""
        logger.info("Test Started: test_update_session_new")
        mock_get_session.return_value = None
        self.session_manager.db.add = MagicMock()
        
        now = datetime.now(timezone.utc)
        expired = now + timedelta(hours=2)
        
        self.session_manager.update_session("new_session_id",now,expired)

        self.session_manager.db.add.assert_called_once()
        
        logger.info("Test Passed: test_update_session_new")
    
    def test_get_session(self):
        """Test if get_session method returns the correct session."""
        
        logger.info("Test Started: test_get_session")

        # Create an actual instance of SessionData
        now = datetime.now(timezone.utc)
        
        mock_session = SessionData(
            session_id=self.session_manager.encrypt("test_session_id"),
            created_at=now - timedelta(hours=1),  # Created an hour ago
            expires_at=now + timedelta(hours=1),)
        logger.info(f"mock_session: {mock_session.session_id}, {mock_session.expires_at}, {mock_session.created_at}")
        
        # Create a mock for the session manager's db query method
        mock_query = MagicMock()
        
        mock_query.populate_existing.return_value = mock_query
        
        # Configure the mock so that first() returns the real SessionData instance
        mock_query.first.return_value = mock_session
        
        # Assign the mock query to the session_manager's db
        self.session_manager.db.query = MagicMock(return_value=mock_query)

        # Call the get_session method
        session = self.session_manager.get_session()

        # Assert that the session is not None and the session_id is correct
        assert session is not None
        assert session.session_id == "test_session_id"

        # Verify that query was called with SessionData and first was called
        self.session_manager.db.query.assert_called_once_with(SessionData)
        mock_query.first.assert_called_once()
        
        logger.info("Test Passed: test_get_session")
    
    def test_get_session_sqlalchemy_error(self):
        """Test if get_session handles SQLAlchemyError."""
        logger.info("TEST Started: test_get_session_sqlalchemy_error")
        # Create a mock for the session manager's db query method
        mock_query = MagicMock()
        
        mock_query.populate_existing.return_value = mock_query
        
        # Raise a SQLAlchemyError when first() is called
        mock_query.first.side_effect = SQLAlchemyError("SQLAlchemy error occurred")
        
        # Assign the mock query to the session_manager's db
        self.session_manager.db.query = MagicMock(return_value=mock_query)

        # Call the get_session method
        with self.assertRaises(SQLAlchemyError):
            self.session_manager.get_session()
            
        logger.info("Test Passed: test_get_session_sqlalchemy_error")
            
    def test_get_session_operational_error(self):
        """Test if get_session handles OperationalError."""
        logger.info("Test Started: test_get_session_operational_error")
        # Create a mock for the session manager's db query method
        mock_query = MagicMock()
        
        mock_query.populate_existing.return_value = mock_query
        
        # Raise an OperationalError when first() is called
        mock_query.first.side_effect = OperationalError("Database connection error", "params", "orig")
        
        # Assign the mock query to the session_manager's db
        self.session_manager.db.query = MagicMock(return_value=mock_query)

        # Call the get_session method
        with self.assertRaises(SQLAlchemyError):
            self.session_manager.get_session()
            
        logger.info("Test Passed: test_get_session_operational_error")
            
    def test_get_session_integrity_error(self):
        """Test if get_session handles IntegrityError."""
        logger.info("Test Started: test_get_session_integrity_error")
        # Create a mock for the session manager's db query method
        mock_query = MagicMock()
        
        mock_query.populate_existing.return_value = mock_query
        
        # Raise an IntegrityError when first() is called
        mock_query.first.side_effect = IntegrityError("Integrity error occurred", "params", "orig")
        
        # Assign the mock query to the session_manager's db
        self.session_manager.db.query = MagicMock(return_value=mock_query)

        # Call the get_session method
        with self.assertRaises(SQLAlchemyError):
            self.session_manager.get_session()
            
        logger.info("Test Passed: test_get_session_integrity_error")
            
    def test_get_session_timeout_error(self):
        """Test if get_session handles TimeoutError."""
        logger.info("Test Started: test_get_session_timeout_error")
        # Create a mock for the session manager's db query method
        mock_query = MagicMock()
        
        # Raise a TimeoutError when first() is called
        mock_query.first.side_effect = TimeoutError("Query timeout occurred")
        
        # Assign the mock query to the session_manager's db
        self.session_manager.db.query = MagicMock(return_value=mock_query)

        # Call the get_session method
        with self.assertRaises(Exception):
            self.session_manager.get_session()
            
        logger.info("Test Passed: test_get_session_timeout_error")

    def test_list_all_sessions(self):
        """Test listing all sessions."""
        logger.info("Test Started: test_list_all_sessions")
        mock_sessions = [
            SessionData(session_id=self.session_manager.encrypt("session1")),
            SessionData(session_id=self.session_manager.encrypt("session2")),
        ]
        mock_query = MagicMock()
    
        # Configure the mock so that first() returns the real SessionData instance
        mock_query.all.return_value = mock_sessions
            
        self.session_manager.db.query = MagicMock(return_value=mock_query)

        sessions = self.session_manager.list_all_sessions()

        self.assertEqual(len(sessions), 2)
        self.assertEqual(sessions[0].session_id, "session1")
        self.assertEqual(sessions[1].session_id, "session2")
        
        logger.info("Test Passed: test_list_all_sessions")
        
    def test_timezone_awareness_after_creation(self):
        """Test if expired is time aware"""
        logger.info("Test Started: test_timezone_awareness_after_creation")
        session_id = "test_session_id"
        now = datetime.now(timezone.utc)
        expired = now + timedelta(hours=2)

        self.session_manager.update_session(session_id, now, expired)

        session = self.session_manager.get_session()
        self.assertIsNotNone(session.created_at.tzinfo)
        self.assertIsNotNone(session.expires_at.tzinfo)
        self.assertEqual(session.created_at.tzinfo.utcoffset(session.created_at) , timedelta(0))
        self.assertEqual(session.expires_at.tzinfo.utcoffset(session.expires_at) , timedelta(0))
        
        logger.info("Test Passed: test_timezone_awareness_after_creation")
        
    def test_validate_session(self):
        """Test session expired time validation"""
        logger.info("Test Started: test_validate_session")
        
        session_id = "test_session_id"
        now = datetime.now(timezone.utc)
        created = now + timedelta(minutes=5)
        expired = created + timedelta(hours=2)
        
        with self.assertRaises(ValueError):
            self.session_manager.update_session(session_id,created,expired)

        session = self.session_manager.get_session()
        self.assertIsNone(session)

        created = now - timedelta(minutes=1)
        expired = created + timedelta(hours=3)
        
        with self.assertRaises(ValueError):
            self.session_manager.update_session(session_id,created,expired)

        session = self.session_manager.get_session()
        self.assertIsNone(session)
        
        logger.info("Test Passed: test_validate_session")
        
    def test_get_session_deletes_expired(self):
        """Test deletion of an overdone session """
        logger.info("Test Started: test_get_session_deletes_expired")
        Session = sessionmaker(bind=self.test_engine)
        db_session = Session()
        
        sessions_before = db_session.query(SessionData).all()
        self.assertEqual(len(sessions_before), 0)
        
        encrypted_session = self.session_manager.encrypt("expired_session")
        now = datetime.now(timezone.utc)
        expired_session = SessionData(
            session_id= encrypted_session,
            created_at=now - timedelta(hours=3),
            expires_at=now - timedelta(minutes=1),
        )
        db_session.add(expired_session)
        db_session.commit()

        sessions_before = db_session.query(SessionData).all()
        self.assertEqual(len(sessions_before), 1)
        self.assertEqual(sessions_before[0].session_id, encrypted_session)

        session = self.session_manager.get_session()
        
        sessions_after = db_session.query(SessionData).all()
        self.assertEqual(len(sessions_after), 0)
        
        self.assertIsNone(session)
        
        logger.info("Test Passed: test_get_session_deletes_expired")
        
class TestTokenManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up an in-memory SQLite database for testing."""
        cls.test_engine = create_engine("sqlite:///:memory:", echo=False)
        cls.TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.test_engine)
        Base.metadata.create_all(bind=cls.test_engine)

    @classmethod
    def tearDownClass(cls):
        """Drop all tables."""
        Base.metadata.drop_all(bind=cls.test_engine)

    def setUp(self):
        """Create a new session for each test."""
        self.db = self.TestSessionLocal()
        self.token_manager = TokenManager()
        self.token_manager.generate_secret_key("939111", "fakepasword")
        self.token_manager.db = self.db
        self.token_manager.clean_token('access')
        self.token_manager.clean_token('refresh')
        self.db.begin()

    def tearDown(self):
        """Rollback any changes and close the session."""
        self.db.rollback()
        self.db.close()

    def test_validate_tokens_success(self):
        """Test successful validation of valid tokens."""
        access_token = TokenData(
            token="valid_access_token",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        refresh_token = RefreshTokenData(
            token="valid_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self.db.add(access_token)
        self.db.add(refresh_token)
        self.db.commit()

        result = self.token_manager.validate_tokens(access_token, refresh_token)
        self.assertTrue(result)
        
    def test_validate_tokens_invalid_expiry(self):
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
        self.db.add(access_token)
        self.db.add(refresh_token)
        self.db.commit()

        with self.assertRaises(ValueError):
            self.token_manager.validate_tokens(access_token, refresh_token)
            
        logger.info("Test Passed: test_validate_tokens_invalid_expiry")
            
    def test_validate_tokens_invalid_expiry_expired(self):
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
        self.db.add(access_token)
        self.db.add(refresh_token)
        self.db.commit()

        with self.assertRaises(ValueError):
            self.token_manager.validate_tokens(access_token, refresh_token)
            
        logger.info("Test Passed: test_validate_tokens_invalid_expiry_expired")
            
    def test_get_valid_token_success(self):
        """Test retrieval of a valid token."""
        logger.info("Test Started: test_get_valid_token_success")
        token = TokenData(
            token=self.token_manager.encrypt("valid_access_token"),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        self.db.add(token)
        self.db.commit()

        result = self.token_manager.get_valid_token("access")
        self.assertIsNotNone(result)
        self.assertEqual(result.token, "valid_access_token")
        
        self.assertIsNotNone(result.expires_at.tzinfo)
        self.assertEqual(result.expires_at.tzinfo.utcoffset(result.expires_at) , timedelta(0))
        
        logger.info("Test Passed: test_get_valid_token_success")
        
    def test_get_valid_refresh_token_success(self):
        """Test retrieval of a valid refresh token."""
        logger.info("Test Started: test_get_valid_refresh_token_success")
        token = RefreshTokenData(
            token=self.token_manager.encrypt("valid_refresh_token"),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        self.db.add(token)
        self.db.commit()

        result = self.token_manager.get_valid_token("refresh")
        self.assertIsNotNone(result)
        self.assertEqual(result.token, "valid_refresh_token")
        
        self.assertIsNotNone(result.expires_at.tzinfo)
        self.assertEqual(result.expires_at.tzinfo.utcoffset(result.expires_at) , timedelta(0))
        
        logger.info("Test Passed: test_get_valid_refresh_token_success")

    def test_get_valid_token_none(self):
        """Test retrieval of a valid token when no valid tokens exist."""
        logger.info("Test Started: test_get_valid_token_none")
        result = self.token_manager.get_valid_token("access")
        self.assertIsNone(result)
        
        logger.info("Test Passed: test_get_valid_token_none")
        
    def test_create_token_success(self):
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
        self.token_manager._TokenManager__create_token(access_token, refresh_token)

        tokens = self.db.query(TokenData).all()
        self.assertEqual(len(tokens), 1)
        self.assertNotEqual(tokens[0].token, "new_access_token")
        
        tokens = self.db.query(RefreshTokenData).all()
        self.assertEqual(len(tokens), 1)
        self.assertNotEqual(tokens[0].token, "new_refresh_token")
        
        logger.info("Test Passed: test_create_token_success")
        
    def test_clean_token(self):
        """Test cleaning tokens of a specific type."""
        logger.info("Test Started: test_clean_token")
        token = TokenData(
            token="to_be_deleted",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        self.db.add(token)
        self.db.commit()

        self.token_manager.clean_token("access")
        tokens = self.db.query(TokenData).all()
        self.assertEqual(len(tokens), 0)
        
        logger.info("Test Passed: test_clean_token")
        
    def test_get_all_tokens(self):
        """Test retrieving all tokens."""
        logger.info("Test Started: test_get_all_tokens")
        access_token = TokenData(
            token=self.token_manager.encrypt("access1"), expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
        )
        refresh_token = RefreshTokenData(
            token=self.token_manager.encrypt("refresh1"), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        self.db.add(access_token)
        self.db.add(refresh_token)
        self.db.commit()

        tokens = self.token_manager.get_all_tokens()
        self.assertIn("access_tokens", tokens)
        self.assertIn("refresh_tokens", tokens)
        self.assertEqual(len(tokens["access_tokens"]), 1)
        self.assertEqual(len(tokens["refresh_tokens"]), 1)
        
        logger.info("Test Passed: test_get_all_tokens")
        
    def test_update_tokens_success(self):
        """Test successfully updating existing tokens."""
        logger.info("Test Started: test_update_tokens_success")
        access_token = TokenData(
            token=self.token_manager.encrypt("old_access_token"), expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
        )
        refresh_token = RefreshTokenData(
            token=self.token_manager.encrypt("old_refresh_token"), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        self.db.add(access_token)
        self.db.add(refresh_token)
        self.db.commit()

        new_access_token = TokenData(
            token="new_access_token", expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)
        )
        new_refresh_token = RefreshTokenData(
            token="new_refresh_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )
        self.token_manager.update_tokens(new_access_token, new_refresh_token)

        updated_access = self.db.query(TokenData).one_or_none()
        updated_refresh = self.db.query(RefreshTokenData).one_or_none()
        
        self.assertEqual(self.token_manager.get_valid_token("access").token, "new_access_token")

        self.assertIsNotNone(updated_access)
        self.assertIsNotNone(updated_refresh)
        
        logger.info("Test Passed: test_update_tokens_success")

    def test_update_tokens_missing_tokens(self):
        """Test creating new tokens if existing tokens are missing."""
        logger.info("Test Started: test_update_tokens_missing_tokens")
        new_access_token = TokenData(
            token="new_access_token", expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)
        )
        new_refresh_token = RefreshTokenData(
            token="new_refresh_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )
        self.token_manager.update_tokens(new_access_token, new_refresh_token)

        created_access = self.db.query(TokenData).one_or_none()
        created_refresh = self.db.query(RefreshTokenData).one_or_none()

        self.assertIsNotNone(created_access)
        self.assertIsNotNone(created_refresh)
        
        self.assertEqual(len(self.db.query(TokenData).all()), 1)
        self.assertEqual(len(self.db.query(RefreshTokenData).all()), 1)
        
        logger.info("Test Passed: test_update_tokens_missing_tokens")

    def test_update_tokens_existing_tokens_already_updated(self):
        """Test no changes when tokens are already up-to-date."""
        logger.info("Test Started: test_update_tokens_existing_tokens_already_updated")
        access_token = TokenData(
            token=self.token_manager.encrypt("current_access_token"), expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)
        )
        refresh_token = RefreshTokenData(
            token=self.token_manager.encrypt("current_refresh_token"), expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )
        self.db.add(access_token)
        self.db.add(refresh_token)
        self.db.commit()
        
        access_token.token = "current_access_token"
        refresh_token.token = "current_refresh_token"

        self.token_manager.update_tokens(access_token, refresh_token)

        updated_access = self.db.query(TokenData).one_or_none()
        updated_refresh = self.db.query(RefreshTokenData).one_or_none()

        self.assertIsNotNone(updated_access)
        self.assertIsNotNone(updated_refresh)
        
        self.assertEqual(len(self.db.query(TokenData).all()), 1)
        self.assertEqual(len(self.db.query(RefreshTokenData).all()), 1)
        
        logger.info("Test Passed: test_update_tokens_existing_tokens_already_updated")

    def test_update_tokens_invalid_tokens(self):
        """Test validation failure when tokens are invalid."""
        logger.info("Test Started: test_update_tokens_invalid_tokens")
        new_access_token = TokenData(
            token="invalid_access_token", expires_at=datetime.now(timezone.utc) - timedelta(minutes=10)
        )
        new_refresh_token = RefreshTokenData(
            token="new_refresh_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )

        with self.assertRaises(ValueError):
            self.token_manager.update_tokens(new_access_token, new_refresh_token)
            
        logger.info("Test Passed: test_update_tokens_invalid_tokens")

    def test_update_tokens_database_error(self):
        """Test database error during token update."""
        logger.info("Test Started: test_update_tokens_database_error")
        new_access_token = TokenData(
            token="new_access_token", expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)
        )
        new_refresh_token = RefreshTokenData(
            token="new_refresh_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )

        with patch.object(self.token_manager.db, "commit", side_effect=SQLAlchemyError("DB error")):
            with self.assertRaises(TokenManagerError):
                self.token_manager.update_tokens(new_access_token, new_refresh_token)
                
        logger.info("Test Passed: test_update_tokens_database_error")

    def test_update_tokens_clean_old_tokens(self):
        """Test cleaning old tokens when missing new tokens."""
        
        logger.info("Test Started: test_update_tokens_clean_old_tokens")
        
        old_encrypted_access_token = self.token_manager.encrypt("old_access_token")
        old_access_token = TokenData(
            token=old_encrypted_access_token, expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
        )
        self.db.add(old_access_token)
        self.db.commit()

        new_access_token = TokenData(
            token="new_access_token", expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)
        )
        new_refresh_token = RefreshTokenData(
            token="new_refresh_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
        )
        self.token_manager.update_tokens(new_access_token, new_refresh_token)

        created_access = self.db.query(TokenData).one_or_none()
        self.assertIsNotNone(created_access)
        
        token = self.token_manager.get_valid_token("access")
        
        self.assertEqual(token.token,"new_access_token")
        
        self.assertEqual(len(self.db.query(TokenData).all()), 1)
        
        logger.info("Test Passed: test_update_tokens_clean_old_tokens")
        
class TestSettingsManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up an in-memory SQLite database for testing."""
        cls.test_engine = create_engine("sqlite:///:memory:", echo=False)
        cls.TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.test_engine)
        Base.metadata.create_all(bind=cls.test_engine)

    @classmethod
    def tearDownClass(cls):
        """Drop all tables."""
        Base.metadata.drop_all(bind=cls.test_engine)

    def setUp(self):
        """Create a new session for each test."""
        
        self.db = self.TestSessionLocal()
        self.settings_manager = SettingsManager()
        self.settings_manager.db = self.db
        self.settings_manager.reset_remember_me()
        logger.info("setup successful")
        # SettingsManager._instances.clear()

    def tearDown(self):
        """Rollback any changes and close the session."""
        self.settings_manager.list_all_settings()
        self.db.rollback()
        self.db.close()
        SettingsManager._instances.clear()

    def test_singleton_behavior(self):
        """Test that SettingsManager adheres to singleton behavior."""
        manager1 = SettingsManager()
        manager2 = SettingsManager()
        self.assertIs(manager1, manager2, "SettingsManager is not a singleton.")
        
    def test_initialization_with_existing_settings(self):
        """Test initialization when settings already exist in the database."""
        logger.info("Test Started: test_initialization_with_existing_settings")
        # Create initial settings
        settings = self.settings_manager.get_user_setting()
        settings.username = "testuser"
        settings.remember_me = True
        self.db.commit()

        self.settings_manager.init_settings_manager()

        self.assertEqual(self.settings_manager.username, "testuser")
        self.assertTrue(self.settings_manager.remember_me)
        
        logger.info("Test Passed: test_initialization_with_existing_settings")
        
    def test_initialization_without_existing_settings(self):
        """Test initialization when no settings exist in the database."""
        logger.info("Started Test: test_initialization_without_existing_settings")
        self.settings_manager.clean_settings()
        self.settings_manager.init_settings_manager()

        self.assertIsNone(self.settings_manager.username)
        self.assertFalse(self.settings_manager.remember_me)
        
        logger.info("Test Passed: test_initialization_without_existing_settings")
        
    def test_initialization_operational_error(self):
        """Test if initialization handles OperationalError."""
        logger.info("Test Started: test_initialization_operational_error")
        mock_query = MagicMock()
        
        mock_query.populate_existing.return_value = mock_query
        
        # Raise an IntegrityError when first() is called
        mock_query.first.side_effect = OperationalError("OperationalError occurred", "params", "orig")
        
        # Assign the mock query to the session_manager's db
        self.settings_manager.db.query = MagicMock(return_value=mock_query)

        # Call the get_session method
        with self.assertRaises(CriticalDatabaseError):
            self.settings_manager.init_settings_manager()
            
        logger.info("Test Passed: test_initialization_operational_error")
            
    def test_initialization_integrity_error(self):
        """Test if initialization handles IntegrityError."""
        logger.info("Test Started: test_initialization_integrity_error")
        mock_query = MagicMock()
        
        mock_query.populate_existing.return_value = mock_query
        
        # Raise an IntegrityError when first() is called
        mock_query.first.side_effect = IntegrityError("OperationalError occurred", "params", "orig")
        
        # Assign the mock query to the session_manager's db
        self.settings_manager.db.query = MagicMock(return_value=mock_query)

        # Call the get_session method
        with self.assertRaises(SettingsManagerError):
            self.settings_manager.init_settings_manager()
            
        logger.info("Test Passed: test_initialization_integrity_error")
            
    def test_set_remember_me_success(self):
        """Test setting the remember_me flag and username."""
        logger.info("Test Started: test_set_remember_me_success")
        self.settings_manager.set_remember_me(True, username="testuser")

        setting = self.db.query(UserSettings).first()
        self.assertEqual(setting.username, "testuser")
        self.assertTrue(setting.remember_me)
        
        logger.info("Test Passed: test_set_remember_me_success")

    def test_set_remember_me_missing_username(self):
        """Test that setting remember_me without a username raises an error."""
        logger.info("Test Started: test_set_remember_me_missing_username")
        with self.assertRaises(ValueError):
            self.settings_manager.set_remember_me(True)
        logger.info("Test Passed: test_set_remember_me_missing_username")
            
    def test_set_remember_me_remeber_false(self):
        """Test setting the remember_me flag and username."""
        logger.info("Test Started: test_set_remember_me_remeber_false")
        with self.assertRaises(ValueError):
            self.settings_manager.set_remember_me(False, username="testuser")
            
        logger.info("Test Passed: test_set_remember_me_remeber_false")
            
    def test_set_remember_me_in_empty_data(self):
        """Test setting the remember_me flag and username."""
        logger.info("Test Started: test_set_remember_me_in_empty_data")
        self.settings_manager.clean_settings()
        self.settings_manager.set_remember_me(True, username="testuser")

        setting = self.db.query(UserSettings).first()
        self.assertEqual(setting.username, "testuser")
        self.assertTrue(setting.remember_me)
        
        logger.info("Test Passed: test_set_remember_me_in_empty_data")
        
    def test_reset_remember_me(self):
        """Test resetting the remember_me flag and username."""
        logger.info("Test Started: test_reset_remember_me")
        # Create initial settings
        self.db.add(UserSettings(username="testuser", remember_me=True))
        self.db.commit()

        self.settings_manager.reset_remember_me()

        setting = self.db.query(UserSettings).first()
        self.assertIsNone(setting.username)
        self.assertFalse(setting.remember_me)
        self.assertIsNone(self.settings_manager.username)
        self.assertFalse(self.settings_manager.remember_me)
        
        logger.info("Test Started: Passed")
        
    def test_reset_remember_me_no_exist_data(self):
        """Test resetting the remember_me flag and username."""
        logger.info("Test Started: test_reset_remember_me_no_exist_data")
        # Create initial settings
        self.settings_manager.clean_settings()

        self.settings_manager.reset_remember_me()

        setting = self.db.query(UserSettings).first()
        self.assertIsNone(setting.username)
        self.assertFalse(setting.remember_me)
        self.assertIsNone(self.settings_manager.username)
        self.assertFalse(self.settings_manager.remember_me)
        
        logger.info("Test Passed: test_reset_remember_me_no_exist_data")
        
    def test_get_user_setting_no_data(self):
        """Test retrieving user settings when none exist in the database."""
        logger.info("Test Started: test_get_user_setting_no_data")
        self.settings_manager.clean_settings()
        setting = self.settings_manager.get_user_setting()
        self.assertIsNone(setting)
        
        logger.info("Test Passed: test_get_user_setting_no_data")
        
    def test_get_user_setting(self):
        """Test retrieving user settings from the database."""
        logger.info("Test Started: test_get_user_setting")
        # Add user settings
        user_settings = self.db.query(UserSettings).populate_existing().first()
        user_settings.remember_me = True
        user_settings.username = "testuser"
        self.db.commit()

        setting = self.settings_manager.get_user_setting()
        self.assertIsNotNone(setting)
        self.assertEqual(setting.username, "testuser")
        self.assertTrue(setting.remember_me)
        
        logger.info("Test Passed: test_get_user_setting")
        
    def test_list_all_users_setting(self):
        """Test getting a list of users"""
        logger.info("Test Started: test_list_all_users_setting")
        self.db.add(UserSettings(username="testuser", remember_me=True))
        self.db.commit()
        
        list_users = self.settings_manager.list_all_settings()
        
        self.assertEqual(len(list_users),2)
        
        logger.info("Test Passed: test_list_all_users_setting")
        
    def test_clean_data_user(self):
        """Test the deletion of all users"""
        logger.info("Test Started: test_clean_data_user")
        self.db.add(UserSettings(username="testuser", remember_me=True))
        self.db.commit()
        
        self.settings_manager.clean_settings()
        
        list_users = self.settings_manager.list_all_settings()
        
        self.assertEqual(len(list_users),0)
        
        logger.info("Test Passed: test_clean_data_user")
        


        
        
 

