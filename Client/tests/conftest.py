import pytest
# from pytestqt.qt_compat import QtQuick
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtCore import QUrl, Qt, QObject 
from PyQt6.QtQuick import QQuickView ,QQuickWindow
from PyQt6.QtQml import QQmlApplicationEngine

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.viewmodels.session_viewmodel import SessionViewModel
from app.database import init_db

import logging
logger = logging.getLogger(__name__)

@pytest.fixture(scope="function", autouse=True)
def setup_test_db():
    """
    Fixture to initialize the test database before each test.
    This ensures a clean state for the database during tests.
    """
    logger.info("Initializing test database.")
    init_db()
    yield
    
    logger.info("Test database setup complete.")

@pytest.fixture(scope="function")
def app():
    """
    Fixture to set up the Qt Application instance.
    Creates a new QGuiApplication instance if not already created.
    Ensures the application is properly closed after the test.
    """
    logger.info("Setting up Qt Application instance.")
    app = QGuiApplication.instance() or QGuiApplication([])
    yield app
    logger.info("Closing Qt Application instance.")
    app.quit()

@pytest.fixture(scope="function")
def app_view(app):
    """
    Fixture to set up the QML view and provide access to the root object, engine, and session view model.
    Ensures the engine and view are properly initialized and cleaned up after the test.

    Yields:
        tuple: (root, engine, sessionview)
            - root: The root object of the QML view.
            - engine: The QQmlApplicationEngine instance.
            - sessionview: The SessionViewModel instance.
    """
    logger.info("Setting up QML view.")

    engine = QQmlApplicationEngine()
    
    sessionview = SessionViewModel()
    
    logger.info(f"Session view model initialized: {sessionview}")

    engine.rootContext().setContextProperty("sessionview", sessionview)
    
    engine.load(QUrl("./main.qml"))
    assert len(engine.rootObjects()) > 0
    
    root = engine.rootObjects()[0]
    
    root.show()
    
    logger.info("QML view is displayed.")
    
    yield root, engine, sessionview
    
    logger.info("Closing QML root object and quitting the application.")
    root.close()
    app.quit()
