from conftest import *
from PyQt6.QtTest import QTest
from PyQt6.QtCore import QPointF

import logging

logger = logging.getLogger(__name__)

class TestMainQml:
    """
    Test suite for verifying the behavior of the main QML components.
    """ 
    @pytest.mark.asyncio    
    async def test_main_window(self,app_view):
        """
        Verifies that all critical child components exist within the main window.
        """
        logger.info("Starting test: test_main_window")
        async for root, engine, sessionview in app_view:

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
            
            logger.info("Test Passed: test_main_window")
        

        