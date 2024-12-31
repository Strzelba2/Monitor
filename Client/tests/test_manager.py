import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
from PyQt6.QtCore import QObject
from app.viewmodels.session_viewmodel import SessionViewModel, SettingsDBManagerError, CriticalDatabaseError
from app.database.settings_db_manager import SettingsDBManager
from app.appStatus.app_state import LoginState
# from app.database import init_db
import logging

logger = logging.getLogger(__name__)


class TestSessionViewModel(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Set up mocks and test environment."""
        # init_db()
        
        self.session_view_model = SessionViewModel()
        self.mock_error_manager = MagicMock()
        self.session_view_model.addEvent = MagicMock()
        self.session_view_model.appStateChanged = MagicMock()
        self.session_view_model._error_manager = self.mock_error_manager


    async def test_initialization_success(self):
        """Test successful initialization of SessionViewModel."""
        logger.info("Test Started: test_initialization_success")
        mock_settings_object = MagicMock()
        mock_manager_class = AsyncMock()
        mock_manager_class.return_value =  mock_settings_object
        
        await self.session_view_model.initialize_managers(mock_manager_class)

        self.assertIsNotNone(self.session_view_model.settings)
        self.assertEqual(self.session_view_model.settings,mock_settings_object)
        mock_manager_class.assert_called_once()
        
        self.mock_error_manager.emit_error.assert_not_called()
        self.mock_error_manager.emit_critical_error.assert_not_called()

        logger.info("Test Passed: test_initialization_success")


    async def test_initialize_managers_settings_manager_error(self):
        """Test handling of SettingsDBManagerError during initialization."""
    
    
        mock_manager_class = AsyncMock()
        mock_manager_class.side_effect = SettingsDBManagerError("Database error")
        
        await self.session_view_model.initialize_managers(mock_manager_class)
        
        self.mock_error_manager.emit_error.assert_called_once_with(
            f"Error initializing {mock_manager_class.__name__}: Database error. Please do not use the switch."
        )
        self.mock_error_manager.emit_critical_error.assert_not_called()
                
        logger.info("Test Passed test_initialize_managers_settings_manager_error")
            
    async def test_initialize_managers_critical_database_error(self):
        """Test handling of CriticalDatabaseError during initialization."""
        logger.info("Test Started test_initialize_managers_critical_database_error")
        mock_manager_class = AsyncMock()
        mock_manager_class.side_effect = CriticalDatabaseError("Critical DB error")
        
        await self.session_view_model.initialize_managers(mock_manager_class)
        
        # Ensure the critical error handler was called
        self.mock_error_manager.emit_critical_error.assert_called_once_with(
            "No connection to the database. Pressing 'OK' will exit the application."
        )
        self.mock_error_manager.emit_error.assert_not_called()
        
        logger.info("Test Passed test_initialize_managers_critical_database_error")
       

    async def test_switch_state_property(self):
        """Test the switch_state property."""
        logger.info("Test Started test_switch_state_propert")
        mock_settings = MagicMock()
        self.session_view_model.settings = mock_settings
        mock_settings.remember_me = True
        self.assertTrue(self.session_view_model.switch_state)
        
        logger.info("Test Passed test_switch_state_propert")

    async def test_text_username_property(self):
        """Test the textUsername property."""
        logger.info("Test Started test_text_username_property")
        mock_settings = MagicMock()
        self.session_view_model.settings = mock_settings
        mock_settings.username = "test_user"
        self.assertEqual(self.session_view_model.textUsername, "test_user")
        
        logger.info("Test Passed test_text_username_property")

    async def test_handle_switch_toggled_on(self):
        """Test handle_switch_toggled when the switch is turned ON."""
        logger.info("Test Started test_handle_switch_toggled_on")
        mock_settings = AsyncMock()
        self.session_view_model.settings = mock_settings
        with patch.object(SessionViewModel, 'switchStateChanged', new_callable=MagicMock) as mock_switchStateChanged:
            self.session_view_model.handle_switch_toggled(True, "test_user")

            await asyncio.sleep(0.5)
            
            mock_settings.set_remember_me.assert_called_once_with(True, "test_user")
            mock_switchStateChanged.emit.assert_called_once_with()
            
        logger.info("Test Passed test_handle_switch_toggled_on")

    async def test_handle_switch_toggled_off(self):
        """Test handle_switch_toggled when the switch is turned OFF."""
        logger.info("Test Started test_handle_switch_toggled_off")
        mock_settings = AsyncMock()
        self.session_view_model.settings = mock_settings
        with patch.object(SessionViewModel, 'switchStateChanged', new_callable=MagicMock) as mock_switchStateChanged:
            with patch.object(SessionViewModel, 'textUsernameChanged', new_callable=MagicMock) as mock_textUsernameChanged:
                self.session_view_model.handle_switch_toggled(False)

                await asyncio.sleep(0.5)
                
                mock_settings.reset_remember_me.assert_called_once()
                mock_textUsernameChanged.emit.assert_called_once_with("Username")
                mock_switchStateChanged.emit.assert_called_once_with()
                
        logger.info("Test Passed test_handle_switch_toggled_off")

    async def test_handle_switch_toggled_error(self):
        """Test handle_switch_toggled handles ValueError."""
        logger.info("Test Started test_handle_switch_toggled_error")
        mock_settings = AsyncMock()
        self.session_view_model.settings = mock_settings
        mock_settings.set_remember_me.side_effect = ValueError("Invalid value")
        
        self.session_view_model.handle_switch_toggled(True, "test_user")
        
        await asyncio.sleep(0.5)
        
        self.mock_error_manager.emit_error.assert_called_once_with("Invalid value")
            
        logger.info("Test Passed test_handle_switch_toggled_error")
        
    def test_verify_password_valid(self):
        """Test that verify_password returns True for a valid password."""
        logger.info("Test Started test_verify_password_valid")
        result = self.session_view_model.verify_password("ValidPassw!ord123_")

        self.assertTrue(result)
        
        logger.info("Test Passed test_verify_password_valid")
        
    def test_verify_password_invalid(self):
        """Test that verify_password returns False for a invalid password."""
        logger.info("Test Started test_verify_password_invalid")
        
        result = self.session_view_model.verify_password("ValidPassw!ord_")

        self.assertFalse(result)
        
        logger.info("Test Passed test_verify_password_invalid")
        
    def test_verify_username_valid(self):
        """Test that verify_username returns True for a valid username."""
        logger.info("Test Started test_verify_username_valid")
        result = self.session_view_model.verify_username("ValidUsername")

        self.assertTrue(result)
        
        logger.info("Test Passed test_verify_username_valid")
        
    def test_verify_username_invalid(self):
        """Test that verify_username returns False and emits an error for an invalid username."""
        logger.info("Test Started test_verify_username_invalid")
        result = self.session_view_model.verify_username("Invalid@Username")

        self.assertFalse(result)
        
        logger.info("Test Passed test_verify_username_invalid")
        
    def test_login_successful(self):
        """Test that verify username and password and emit appStateChanged signal"""
        logger.info("Test Started test_login_successful")
        self.session_view_model.login("ValidUsername", "ValidPassw!ord123_")

        self.session_view_model.appStateChanged.emit.assert_called_once_with(LoginState.TWO_FACTORY)
        logger.info("Test Passed test_login_successful")
        
    def test_login_unsuccessful(self):
        """Test that login does not proceed if validation fails."""
        logger.info("Test Started test_login_unsuccessful")
        self.session_view_model.login("ValidUsername", "ValidPassw!ord_")
        
        self.session_view_model.appStateChanged.appStateChanged.emit.assert_not_called()
        self.mock_error_manager.emit_error.assert_called_once_with('Password must contain at least one digit.')
        logger.info("Test Passed test_login_unsuccessful")
        
    def test_totp_login_successful(self):
        """Test that totp_login validates the code and emits the correct signals."""
        logger.info("Test Started test_totp_login_successful")
        self.session_view_model.login("ValidUsername", "ValidPassw!ord123_")
        
        self.session_view_model.totp_login("123456")
        
        self.session_view_model.addEvent.emit.assert_called_once_with(
            0, "login", {'username': 'ValidUsername', 'password': 'ValidPassw!ord123_', 'code': '123456'}, self.session_view_model.__class__.__name__
        )
        logger.info("Test Passed test_totp_login_successful")
        
    def test_totp_login_invalid_totp(self):
        """Test that totp_login with invalid code"""
        logger.info("Test Started test_totp_login_invalid_totp")
        
        self.session_view_model.login("ValidUsername", "ValidPassw!ord123_")
        
        self.session_view_model.totp_login("abcdefg")
        
        expected_calls = [
            unittest.mock.call(LoginState.TWO_FACTORY),
            unittest.mock.call(LoginState.LOGGED_OUT),
        ]
   
        self.session_view_model.appStateChanged.emit.assert_has_calls(expected_calls)
        self.mock_error_manager.emit_error.assert_called_once_with('2FA code must consist of exactly 6 digits.')
   
        self.session_view_model.addEvent.emit.assert_not_called()
        
        logger.info("Test Passed test_totp_login_invalid_totp")
        
    def test_login_failed(self):
        """Test that verify if  login_failed emit appStateChanged signal"""
        logger.info("Test Started test_login_failed")
        
        self.session_view_model.login_failed("Some kind of error")
        
        self.session_view_model.appStateChanged.emit.assert_called_once_with(LoginState.LOGIN_FAILED)
        self.mock_error_manager.emit_error.assert_called_once_with("Some kind of error")
        
        logger.info("Test Passed test_login_failed")
        
    def login_success(self):
        """Test that verify if  login_success emit appStateChanged signal"""
        logger.info("Test Started login_success")
        self.session_view_model.login_success()
        
        self.session_view_model.appStateChanged.emit.assert_called_once_with(LoginState.LOGGED_IN)
        
        logger.info("Test Passed login_success")
        
    def test_logout(self):
        """Test that verify if logout emit event signal"""
        logger.info("Test Started test_logout")
        self.session_view_model.logout()
        
        self.session_view_model.addEvent.emit.assert_called_once_with(
            0, "logout", {}, self.session_view_model.__class__.__name__
        )
        logger.info("Test Passed test_logout")
        
    def test_logout_success(self):
        """Test that verify if  logout_success emit logoutSuccess signal"""
        logger.info("Test Started test_logout_success")
        self.session_view_model.logoutSuccess = MagicMock()
        
        self.session_view_model.logout_success()
        
        self.session_view_model.logoutSuccess.emit.assert_called_once()
        logger.info("Test Passed test_logout_success")
            
