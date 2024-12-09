import unittest
from unittest.mock import MagicMock, patch
from PyQt6.QtCore import QObject
from app.viewmodels.session_viewmodel import SessionViewModel, SettingsManagerError, CriticalDatabaseError
from app.database.settings_manager import SettingsManager
from app.database import init_db
import logging

logger = logging.getLogger(__name__)


class TestSessionViewModel(unittest.TestCase):
    def setUp(self):
        """Set up mocks and test environment."""
        init_db()
        
        self.mock_settings = MagicMock()
        self.mock_session_manager = MagicMock()
        self.mock_token_manager = MagicMock()

        self.settings_manager_patch = patch("app.viewmodels.session_viewmodel.SettingsManager", return_value=self.mock_settings)
        self.session_manager_patch = patch("app.viewmodels.session_viewmodel.SessionManager", return_value=self.mock_session_manager)
        self.token_manager_patch = patch("app.viewmodels.session_viewmodel.TokenManager", return_value=self.mock_token_manager)

        self.settings_manager_patch.__name__ = "SettingsManager"
        
        self.mock_settings_manager_class = self.settings_manager_patch.start()
        self.mock_session_manager_class = self.session_manager_patch.start()
        self.mock_token_manager_class = self.token_manager_patch.start()
        
        self.mock_settings_manager_class.__name__ = "SettingsManager"
        self.mock_session_manager_class.__name__ = "SessionManager"
        self.mock_token_manager_class.__name__ = "TokenManager"

        self.addCleanup(self.settings_manager_patch.stop)
        self.addCleanup(self.session_manager_patch.stop)
        self.addCleanup(self.token_manager_patch.stop)

    def test_initialization_success(self):
        """Test successful initialization of SessionViewModel."""
        logger.info("Test Started: test_initialization_success")
        model = SessionViewModel()

        self.assertIsNotNone(model.settings)
        self.assertIsNotNone(model.session_manager)
        self.assertIsNotNone(model.token_manager)
        self.assertEqual(model.settings,self.mock_settings)
        self.assertEqual(model.session_manager,self.mock_session_manager)
        self.assertEqual(model.token_manager,self.mock_token_manager)
        self.mock_settings_manager_class.assert_called_once()
        self.mock_session_manager_class.assert_called_once()
        self.mock_token_manager_class.assert_called_once()

        logger.info("Test Passed: test_initialization_success")

    def test_initialize_managers_success(self):
        """Test successful manager initialization."""
        logger.info("Test Started: test_initialize_managers_success")
        model = SessionViewModel()
        manager_instance = model.initialize_managers(SettingsManager)
        self.assertIs(type(manager_instance), SettingsManager)
        
        logger.info("Test Passed: test_initialize_managers_success")

    def test_initialize_managers_settings_manager_error(self):
        """Test handling of SettingsManagerError during initialization."""
        
        logger.info("Started test test_initialize_managers_settings_manager_error")
        with patch("app.viewmodels.session_viewmodel.SettingsManager", side_effect=SettingsManagerError("Mock error")) as mock_settings:
            mock_settings.__name__ = "SettingsManager"
            with patch.object(SessionViewModel, 'showError', new_callable=MagicMock) as mock_show_error:
                model = SessionViewModel()
                
                # Check that settings were not initialized
                self.assertIsNone(model.settings)
                
                # Verify that showError.emit was called with the expected message
                mock_show_error.emit.assert_called_once_with(
                    "Error initializing SettingsManager: Mock error. Please do not use the switch."
                )
                
                # Verify that SettingsManager was called
                mock_settings.assert_called_once()
                
        logger.info("Test Passed test_initialize_managers_settings_manager_error")
            
    def test_initialize_managers_critical_database_error(self):
        """Test handling of CriticalDatabaseError during initialization."""
        logger.info("Test Started test_initialize_managers_critical_database_error")
        with patch("app.viewmodels.session_viewmodel.SettingsManager", side_effect=CriticalDatabaseError("DB Error")) as mock_settings:
            mock_settings.__name__ = "SettingsManager"
            with patch.object(SessionViewModel, 'showCriticalError', new_callable=MagicMock) as mock_critical_error:
                model = SessionViewModel()
        
                self.assertIsNone(model.settings)
                
                mock_critical_error.emit.assert_called_once_with(
                    "No connection to the database. Pressing 'OK' will exit the application."
                )
                
                # Verify that SettingsManager was called
                mock_settings.assert_called_once()
        
        logger.info("Test Passed test_initialize_managers_critical_database_error")
       

    def test_switch_state_property(self):
        """Test the switch_state property."""
        logger.info("Test Started test_switch_state_propert")
        model = SessionViewModel()
        self.mock_settings.remember_me = True
        self.assertTrue(model.switch_state)
        
        logger.info("Test Passed test_switch_state_propert")

    def test_text_username_property(self):
        """Test the textUsername property."""
        logger.info("Test Started test_text_username_property")
        model = SessionViewModel()
        self.mock_settings.username = "test_user"
        self.assertEqual(model.textUsername, "test_user")
        
        logger.info("Test Passed test_text_username_property")

    def test_handle_switch_toggled_on(self):
        """Test handle_switch_toggled when the switch is turned ON."""
        logger.info("Test Started test_handle_switch_toggled_on")
        model = SessionViewModel()
        with patch.object(SessionViewModel, 'switchStateChanged', new_callable=MagicMock) as mock_switchStateChanged:
            model.handle_switch_toggled(True, "test_user")

            self.mock_settings.set_remember_me.assert_called_once_with(True, "test_user")
            mock_switchStateChanged.emit.assert_called_once_with()
            
        logger.info("Test Passed test_handle_switch_toggled_on")

    def test_handle_switch_toggled_off(self):
        """Test handle_switch_toggled when the switch is turned OFF."""
        logger.info("Test Started test_handle_switch_toggled_off")
        model = SessionViewModel()
        with patch.object(SessionViewModel, 'switchStateChanged', new_callable=MagicMock) as mock_switchStateChanged:
            with patch.object(SessionViewModel, 'textUsernameChanged', new_callable=MagicMock) as mock_textUsernameChanged:
                model.handle_switch_toggled(False)

                self.mock_settings.reset_remember_me.assert_called_once()
                mock_textUsernameChanged.emit.assert_called_once_with("Username")
                mock_switchStateChanged.emit.assert_called_once_with()
                
        logger.info("Test Passed test_handle_switch_toggled_off")

    def test_handle_switch_toggled_error(self):
        """Test handle_switch_toggled handles ValueError."""
        logger.info("Test Started test_handle_switch_toggled_error")
        model = SessionViewModel()
        self.mock_settings.set_remember_me.side_effect = ValueError("Invalid value")
        
        with patch.object(model, "showError", MagicMock()) as mock_show_error:
            model.handle_switch_toggled(True, "test_user")
            mock_show_error.emit.assert_called_once_with("Invalid value")
            
        logger.info("Test Passed test_handle_switch_toggled_error")

