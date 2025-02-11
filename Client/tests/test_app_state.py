from app.appStatus.app_state import SessionState, LoginState
from app.appStatus.app_state_manager import AppState
import unittest
from unittest.mock import MagicMock, patch
import logging

logger = logging.getLogger(__name__)

class TestAppState(unittest.TestCase):
    def setUp(self):
        """Set up test case environment."""
        AppState._instance = None
        self.app_state = AppState()
        self.app_state.showAppStateChanged = MagicMock() 
        
    def TearDown(self):
        AppState._instance = None
        super().tearDown()

    def test_initial_state(self):
        """Test that the initial state is set correctly."""
        logger.info("Test Started: test_initial_state")
        self.assertEqual(self.app_state._state, LoginState.LOGGED_OUT)
        self.assertEqual(self.app_state._session_state, SessionState.SESSION_UNAVAIABLE)
        
        logger.info("Test Passed: test_initial_state")

    def test_get_state(self):
        """Test retrieving the current state."""
        logger.info("Test Started: test_get_state")
        state = self.app_state.get_state()
        self.assertEqual(state, LoginState.LOGGED_OUT.value)
        
        logger.info("Test Passed: test_get_state")

    def test_set_state(self):
        """Test setting a new state."""
        logger.info("Test Started: test_set_state")
        self.app_state.set_state(LoginState.LOGGED_IN)
        self.assertEqual(self.app_state._state, LoginState.LOGGED_IN)
        self.app_state.showAppStateChanged.emit.assert_called_once()
        
        logger.info("Test Passed: test_set_state")

    def test_signal_emission_on_state_change(self):
        """Test that the signal is emitted when the state changes."""
        logger.info("Test Started: test_signal_emission_on_state_change")
        
        self.app_state.set_state(LoginState.LOGGED_IN)
        self.app_state.showAppStateChanged.emit.assert_called_once()
        
        logger.info("Test Passed: test_signal_emission_on_state_change")