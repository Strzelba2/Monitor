from PyQt6.QtCore import QObject, pyqtSignal

class SignalManager():
    """
    Manages custom signals for communication between objects in a PyQt application.

    This class defines various signals that can be emitted to notify other parts of the
    application about changes in state, username, or errors. These signals allow objects
    to communicate with each other without direct dependencies, facilitating better 
    decoupling in the application's design.
    """
    switchStateChanged = pyqtSignal()
    textUsernameChanged = pyqtSignal(str)
    showError = pyqtSignal(str)
    showCriticalError = (pyqtSignal(str))



 