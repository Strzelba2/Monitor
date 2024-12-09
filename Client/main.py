from PyQt6.QtGui import QGuiApplication
from PyQt6.QtQml import QQmlApplicationEngine
from PyQt6.QtCore import QtMsgType, qInstallMessageHandler

from app.database import init_db
from app.viewmodels.session_viewmodel import SessionViewModel

import sys
import os
import logging

# Set the environment variable for the Qt Quick backend to use software rendering.
os.environ["QT_QUICK_BACKEND"] = "software" 

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


def main():
    """
    The main entry point of the application.
    
    - Initializes the database.
    - Sets up the QML application engine.
    - Loads the main QML file and connects the QML environment to Python.
    - Starts the PyQt6 application loop.
    """
    logger.info("Application starting...")
    
    # Initialize the database
    init_db()
    logger.info("Database initialized successfully.")
    
    # Install the QML message handler for logging QML messages
    qInstallMessageHandler(qml_message_handler)
    logger.debug("QML message handler installed.")

    # Create the application instance
    app = QGuiApplication(sys.argv)
    logger.info("QGuiApplication instance created.")
    
    # Create and configure the QML engine
    engine = QQmlApplicationEngine()
    engine.quit.connect(app.quit)
    logger.debug("QML engine created and quit signal connected to app.quit.")

    # Initialize the SessionViewModel and set it as a context property in QML
    sessionview = SessionViewModel()
    engine.rootContext().setContextProperty("sessionview", sessionview)
    logger.debug("SessionViewModel set in QML context.")
     
    # Load the main QML file   
    engine.load('main.qml')

    # Check if the root QML objects are loaded
    if not engine.rootObjects():
        logger.error("No root objects were loaded in the QML engine. Exiting application.")
        sys.exit(-1)
        
    # Start the Qt application event loop
    logger.info("Starting application event loop.")
    sys.exit(app.exec())

if __name__ == "__main__":
    main()