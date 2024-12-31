from PyQt6.QtGui import QGuiApplication
from PyQt6.QtQml import QQmlApplicationEngine
from PyQt6.QtCore import QtMsgType, qInstallMessageHandler
from qasync import QEventLoop, run

from app.database import init_db
from app.viewmodels.session_viewmodel import SessionViewModel
from app.models.event_manager import CentralQueueManager
from app.models.user_manager import UserManager
from app.appStatus.app_state_manager import AppState
from app.network.Session_client import SessionClient
from app.signals.signal_connection import SignalConnectionManager
from app.database.settings_db_manager import SettingsDBManager

import sys
import os
import logging
import asyncio

# Set the environment variable for the Qt Quick backend to use software rendering.
os.environ["QT_QUICK_BACKEND"] = "software" 
os.environ.setdefault("QT_API", "PyQt6")

# Configure the logging system
BASE_DIR = os.getcwd()
logs_path = os.path.join(BASE_DIR, "logs","logs.log")

logging.basicConfig(
    filename=logs_path,
    filemode="a",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger()

# Configure a console handler for real-time logging in the console
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(levelname)s - %(module)s(%(process)d/%(thread)d) -  %(message)s"))
logger.addHandler(console_handler)

def qml_message_handler(mode: QtMsgType, context, message: str) -> None:
    """
    Handles QML messages and logs them appropriately.
    
    :param mode: The message type from QML (e.g., info, warning, critical).
    :param context: The context of the QML message.
    :param message: The actual message string from QML.
    """
    if mode == QtMsgType.QtInfoMsg:
        logger.info(f"QML: {message}")
    elif mode == QtMsgType.QtWarningMsg:
        logger.warning(f"QML Warning: {message}")
    elif mode == QtMsgType.QtCriticalMsg:
        logger.error(f"QML Critical: {message}")
    elif mode == QtMsgType.QtFatalMsg:
        logger.critical(f"QML Fatal: {message}")
        sys.exit(1)
    else:
        logger.info(f"QML (other): {message}")

async def main():
    """
    The main entry point of the application.
    
    - Initializes the database.
    - Sets up the QML application engine.
    - Loads the main QML file and connects the QML environment to Python.
    - Starts the PyQt6 application loop.
    """
    logger.info("Application starting...")

    # Initialize the database
    await init_db()
    logger.info("Database initialized successfully.")
    
    # Install the QML message handler for logging QML messages
    qInstallMessageHandler(qml_message_handler)
    logger.debug("QML message handler installed.")
    
    logger.info("QGuiApplication instance created.")
    
    # Create and configure the QML engine
    engine = QQmlApplicationEngine()

    engine.quit.connect(lambda: logger.info("START QUIT"))
    engine.quit.connect(lambda: sys.exit(asyncio.get_running_loop().stop()))
    try:
        user_manager = UserManager()
        await user_manager.clear_tokens_and_session()
    except Exception as e:
        logger.info(f"user_manager error :  {str(e)}")
    
    logger.info("start event_manager = CentralQueueManager()")
    event_manager = CentralQueueManager()
    asyncio.create_task(event_manager.start())
    
    logger.info("started  event_manager = CentralQueueManager() with success")

    logger.info("start session_client = SessionClient()")
    session_client = SessionClient()
    await session_client.create_session()
    logger.info("started  session_client.create_session() with success")
    
    logger.info("start sessionview = SessionViewModel()")  
    # Initialize the SessionViewModel and set it as a context property in QML
    sessionview = SessionViewModel()
    await sessionview.initialize_managers(SettingsDBManager)
    engine.rootContext().setContextProperty("sessionview", sessionview)
    logger.debug("SessionViewModel set in QML context.")
    
    # Initialize AppState
    logger.info("start  appstatus = AppState()")
    appstatus = AppState()
    engine.rootContext().setContextProperty("appstatus", appstatus)
    logger.debug("AppState set in QML context.")
    
    # Load the main QML file  
    logger.info("start  engine.load('main.qml')") 
    engine.load('main.qml')
    
    signal_manager = SignalConnectionManager(sessionview,appstatus,event_manager,session_client,user_manager)
    signal_manager.connect_signals()

    # Check if the root QML objects are loaded
    if not engine.rootObjects():
        logger.error("No root objects were loaded in the QML engine. Exiting application.")
        sys.exit(-1)

    app.aboutToQuit.connect(lambda: logger.info("Application is closing..."))    
    app.aboutToQuit.connect(session_client.close_session)
    app.aboutToQuit.connect(user_manager.close_clear_tokens_and_session)
    app.aboutToQuit.connect(event_manager.stop) 
    app_close_event = asyncio.Event()
    app.aboutToQuit.connect(app_close_event.set)
    
    # Start the Qt application event loop
    logger.info("Starting application event loop.")
    await app_close_event.wait()

if __name__ == "__main__":
    
    app = QGuiApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    run(main())
