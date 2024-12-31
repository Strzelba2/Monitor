import unittest
from unittest.mock import MagicMock, patch, mock_open , call
from app.exceptions.error_manager import ErrorManager
from config.config import Config
import logging

logger = logging.getLogger(__name__)

class MockConfig:
    EXCEPTION_EVENT_FILE = "mock_registry.json"

class TestSingletonMeta(unittest.TestCase):
    
    def setUp(self):
        ErrorManager._instances = {}
        
    def tearDown(self):
        pass
    
    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.path.exists", return_value=False)     
    def test_singleton_behavior(self, mock_exists,mock_open_file, mock_getsize):
        """Ensure that only one instance of the class is created."""
        logger.info("Test Started test_singleton_behavior")
        instance1 = ErrorManager()
        instance2 = ErrorManager()
        self.assertIs(instance1, instance2, "SingletonMeta failed to enforce a single instance.")
        
        logger.info("Test Passed test_singleton_behavior")
       
    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.path.exists", return_value=False)   
    def test_load_registry_creates_file(self, mock_exists,mock_open_file, mock_getsize):
        """Test that a new file is created if it doesn't exist."""
        logger.info("Test Started test_load_registry_creates_file")
        
        self.error_manager = ErrorManager()
        mock_open_file.assert_called_with("mock_registry.json", "w")
        mock_open_file().write.assert_called_once_with("{}")
        
        logger.info("Test Passed test_load_registry_creates_file")
        
    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")   
    @patch("builtins.open", new_callable=mock_open, read_data='{}')
    @patch("os.path.exists", return_value=True) 
    def test_load_registry_empty_data(self, mock_exists, mock_open_file, mock_getsize):
        """Test loading registry from an empty file with data."""
        logger.info("Test Started test_load_registry_empty_data")
        self.error_manager = ErrorManager()
        self.assertEqual(self.error_manager.registry, {},"Failed to load registry with empty data.")
        
        logger.info("Test Passed test_load_registry_empty_data")
        
    @patch("os.path.getsize", return_value=1) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")   
    @patch("builtins.open", new_callable=mock_open, read_data='{"test-event": 1}')
    @patch("os.path.exists", return_value=True) 
    def test_load_registry_existing_data(self, mock_exists, mock_open_file, mock_getsize):
        """Test loading registry from an existing file with data."""
        logger.info("Test Started  test_load_registry_existing_data")
        self.error_manager = ErrorManager()
        self.assertEqual(self.error_manager.registry, {"test-event": 1},"Failed to load registry with existing data.")
        
        logger.info("Test Passed  test_load_registry_existing_data")
        
    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")   
    @patch("builtins.open", side_effect = IOError("Failed to read file ") )
    @patch("os.path.exists", return_value=True) 
    def test_load_registry_exception_data(self, mock_exists, mock_open_file, mock_getsize):
        """Test loading registry from an empty file with data."""
        logger.info("Test Started  test_load_registry_exception_data")
        
        self.error_manager = ErrorManager()
        self.assertEqual(self.error_manager.registry, {},"Failed to load registry with exception data.")
        
        logger.info("Test Passed  test_load_registry_exception_data")
        
        
    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")   
    @patch("builtins.open", new_callable=mock_open, read_data='{}')
    @patch("os.path.exists", return_value=True) 
    def test_save_registry( self, mock_exists, mock_open_file, mock_getsize):
        """Test saving the registry to a file."""
        logger.info("Test Started  test_save_registry")
        
        self.error_manager = ErrorManager()
        self.error_manager.registry = {"test-event": 1}
        with patch("builtins.open", new_callable=mock_open) as mock_open_file:
            self.error_manager._save_registry()
            expected_calls = [
                call('{'),
                call('\n    '),
                call('"test-event"'),
                call(': '),
                call('1'),
                call('\n'),
                call('}')
            ]
            assert mock_open_file().write.call_args_list == expected_calls
            
        logger.info("Test Passed  test_save_registry")
     
    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")   
    @patch("builtins.open", new_callable=mock_open, read_data='{}')
    @patch("os.path.exists", return_value=True)        
    def test_track_exception_empty_registry(self, mock_exists, mock_open_file, mock_getsize):
        """Test tracking an exception and updating the registry."""
        logger.info("Test Started  test_track_exception_empty_registry")
        
        self.error_manager = ErrorManager()
        with patch("builtins.open", new_callable=mock_open) as mock_open_file:
            count = self.error_manager.track_exception("TestModule", "ErrorType")
            self.assertEqual(count, 1, "Failed to track exception correctly.")
            self.assertEqual(self.error_manager.registry, {"TestModule-ErrorType": 1}, "Registry not updated correctly.")
            
        logger.info("Test Passed  test_track_exception_empty_registry")
            
    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")   
    @patch("builtins.open", new_callable=mock_open, read_data='{}')
    @patch("os.path.exists", return_value=True)        
    def test_track_exception_existing_registry(self, mock_exists, mock_open_file, mock_getsize):
        """Test tracking an exception and updating the registry."""
        logger.info("Test Started  test_track_exception_existing_registry")
        
        self.error_manager = ErrorManager()
        self.error_manager.registry = {"TestModule-ErrorType": 1}
        with patch("builtins.open", new_callable=mock_open) as mock_open_file:
            count = self.error_manager.track_exception("TestModule", "ErrorType")
            self.assertEqual(count, 2, "Failed to track exception correctly.")
            self.assertEqual(self.error_manager.registry, {"TestModule-ErrorType": 2}, "Registry not updated correctly.")
      
        logger.info("Test Passed  test_track_exception_existing_registry")
              
    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")   
    @patch("builtins.open", new_callable=mock_open, read_data='{}')
    @patch("os.path.exists", return_value=True)        
    def test_track_exception_exception_save_registry(self, mock_exists, mock_open_file, mock_getsize):
        """Test tracking an exception and updating the registry."""
        logger.info("Test Started  test_track_exception_exception_save_registry")
        
        self.error_manager = ErrorManager()
        with patch("builtins.open", new_callable=mock_open) as mock_open_file:
            mock_open_file.side_effect = IOError("Failed to save file ")
            count = self.error_manager.track_exception("TestModule", "ErrorType")
            self.assertEqual(count, None, "Failed to track exception correctly.")
            self.assertEqual(self.error_manager.registry, {}, "Registry not updated correctly.")
            
        logger.info("Test Passed  test_track_exception_exception_save_registry")
    
    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")   
    @patch("builtins.open", new_callable=mock_open, read_data='{}')
    @patch("os.path.exists", return_value=True)         
    def test_reset_exception(self, mock_exists, mock_open_file, mock_getsize):
        """Test clearing exceptions for specified modules."""
        logger.info("Test Started  test_reset_exception")
        
        self.error_manager = ErrorManager()
        self.error_manager.registry = {
            "SessionClient-ErrorType": 1,
            "OtherModule-ErrorType": 2
        }
        self.error_manager.reset_exception()
        self.assertNotIn("SessionClient-ErrorType", self.error_manager.registry, "Failed to remove SessionClient events.")
        self.assertIn("OtherModule-ErrorType", self.error_manager.registry, "Unrelated events were removed.")
        
        logger.info("Test Passed  test_reset_exception")
        
    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")   
    @patch("builtins.open", new_callable=mock_open, read_data='{}')
    @patch("os.path.exists", return_value=True) 
    def test_emit_error(self, mock_exists, mock_open_file, mock_getsize):
        """Test emitting a non-critical error."""
        logger.info("Test Started  test_emit_error")
        
        self.error_manager = ErrorManager()

        mock_callback = MagicMock()
        self.error_manager.showError.connect(mock_callback)
        self.error_manager.emit_error("Test error")
        mock_callback.assert_called_once_with("Test error")
        
        logger.info("Test Passed  test_emit_error")

    @patch("os.path.getsize", return_value=0) 
    @patch.object(Config, "EXCEPTION_EVENT_FILE", "mock_registry.json")   
    @patch("builtins.open", new_callable=mock_open, read_data='{}')
    @patch("os.path.exists", return_value=True)
    def test_emit_critical_error(self, mock_exists, mock_open_file, mock_getsize):
        """Test emitting a critical error."""
        logger.info("Test Started  test_emit_critical_error")
        
        self.error_manager = ErrorManager()

        mock_callback = MagicMock()
        self.error_manager.showCriticalError.connect(mock_callback)
        self.error_manager.emit_critical_error("Critical error")
        mock_callback.assert_called_once_with("Critical error")
        
        logger.info("Test Passed  test_emit_critical_error")
            
    