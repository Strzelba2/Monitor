from conftest import *
from PyQt6.QtTest import QTest
from PyQt6.QtCore import QPointF

import logging

logger = logging.getLogger(__name__)

class TestMainQml:
    """
    Test suite for verifying the behavior of the main QML components.
    """
    def test_main_window_loaded(self,app_view):
        """
        Verifies the main window is loaded and its properties are correctly set.
        """
        logger.info("Starting test: test_main_window_loaded")
        root, engine, sessionview = app_view
        QTest.qWait(1000)
        assert root is not None
        assert root.property("title") == "Login"
        
        logger.info("Test Passed: test_main_window_loaded")
        
    def test_child_exist(self,app_view):
        """
        Verifies that all critical child components exist within the main window.
        """
        logger.info("Starting test: test_child_exist")
        root, engine, sessionview = app_view

        QTest.qWait(500)
        
        loader = root.findChild(QObject, "myLoader")
        assert loader is not None, "Loader not found."
        
        loaded_item = loader.property("item")
        assert loaded_item is not None, "Object not loaded by Loader."
        
        btn_close = loaded_item.findChild(QObject, "btnClose")
        assert btn_close is not None, "No btnClose found."

        text_username = loaded_item.findChild(QObject, "textUsername")
        assert text_username is not None, "No textUsername found."

        text_password = loaded_item.findChild(QObject, "textPassword")
        assert text_password is not None, "No textPassword found."

        remember_me_switch = loaded_item.findChild(QObject, "rememberMe")
        assert remember_me_switch is not None, "No rememberMe found."

        btn_login = loaded_item.findChild(QObject, "btnLogin")
        assert btn_login is not None, "No btnLogin found."
        
        logger.info("Test Passed: test_child_exist")
        
    def test_remember_me_without_user(self,app_view):
        """
        Tests the behavior of the 'Remember Me' switch when no user is set.
        """
        logger.info("Starting test: test_remember_me_without_user")
        root, engine, sessionview = app_view

        QTest.qWait(1000)

        loader = root.findChild(QObject, "myLoader")
        assert loader is not None, "Loader not found."
        
        loaded_item = loader.property("item")
        assert loaded_item is not None, "Object not loaded by Loader."
        
        remember_me_switch = loaded_item.findChild(QObject, "rememberMe")
        assert remember_me_switch is not None, "No rememberMe found."
        
        indicator = remember_me_switch.findChild(QObject, "rememberMeInd")
        assert indicator is not None, "No indicator found for the switch."
        
        assert isinstance(root, QQuickWindow)

        local_pos = indicator.mapToScene(QPointF(0, 0)).toPoint()
        indicator_pos = indicator.mapToScene(QPointF(0, 0))
        global_pos = root.mapToGlobal(indicator_pos.toPoint())

        QTest.mouseClick(root, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, local_pos)
        
        QTest.qWait(500)
        
        popup_main = root.findChild(QObject, "popupMain")
        assert popup_main is not None, "PopupMain was not opened when Switch was clicked."
        
        logger.info("Test Passed:  test_remember_me_without_user")
        
        
    def test_remember_me_with_user(self,app_view):
        """
        Tests the 'Remember Me' functionality when a user is set.
        """
        logger.info("Starting test: test_remember_me_with_user")
        root, engine, sessionview = app_view

        QTest.qWait(1000)

        loader = root.findChild(QObject, "myLoader")
        assert loader is not None, "Loader not found."
        
        loaded_item = loader.property("item")
        assert loaded_item is not None, "Object not loaded by Loader."
        
        remember_me_switch = loaded_item.findChild(QObject, "rememberMe")
        assert remember_me_switch is not None, "No rememberMe found."
        
        indicator = remember_me_switch.findChild(QObject, "rememberMeInd")
        assert indicator is not None, "No indicator found for the switch."
        
        text_username = loaded_item.findChild(QObject, "textUsername")
        assert text_username is not None, "No textUsername field found."

        text_username.setProperty("text", "Artur")
        
        assert isinstance(root, QQuickWindow)

        local_pos = indicator.mapToScene(QPointF(0, 0)).toPoint()
        indicator_pos = indicator.mapToScene(QPointF(0, 0))
        global_pos = root.mapToGlobal(indicator_pos.toPoint())

        QTest.mouseClick(root, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, local_pos)
        
        QTest.qWait(800)
        
        assert text_username.property("text") == "Artur", "Text was not set correctly."
        assert remember_me_switch.property("checked") == True, "Switch state should by True"
        
        logger.info("Test Passed: test_remember_me_with_user")
        
    def test_remember_me_clear_existing_user(self,app_view):
        """
        Verifies that the 'Remember Me' switch clears the username when toggled off.
        """
        logger.info("Starting test: test_remember_me_clear_existing_user")
        root, engine, sessionview = app_view

        QTest.qWait(1000)

        loader = root.findChild(QObject, "myLoader")
        assert loader is not None, "Loader not found."
        
        loaded_item = loader.property("item")
        assert loaded_item is not None, "Object not loaded by Loader."
        
        remember_me_switch = loaded_item.findChild(QObject, "rememberMe")
        assert remember_me_switch is not None, "No rememberMe found."
        
        indicator = remember_me_switch.findChild(QObject, "rememberMeInd")
        assert indicator is not None, "No indicator found for the switch."
        
        text_username = loaded_item.findChild(QObject, "textUsername")
        assert text_username is not None, "No textUsername field found."

        assert text_username.property("text") == "Artur", "Text was not set correctly."
        
        assert isinstance(root, QQuickWindow)

        local_pos = indicator.mapToScene(QPointF(0, 0)).toPoint()
        indicator_pos = indicator.mapToScene(QPointF(0, 0))
        global_pos = root.mapToGlobal(indicator_pos.toPoint())

        QTest.mouseClick(root, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, local_pos)
        
        QTest.qWait(500)

        assert remember_me_switch.property("checked") == False, "Switch state should by False"
        assert text_username.property("text") != "Artur", "Text should be empty."
        
        logger.info("Test Passed: test_remember_me_clear_existing_user")
        