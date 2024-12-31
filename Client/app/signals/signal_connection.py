from app.viewmodels.session_viewmodel import SessionViewModel
from app.appStatus.app_state_manager import AppState
from app.models.event_manager import CentralQueueManager
from app.network.Session_client import SessionClient
from app.models.user_manager import UserManager


class SignalConnectionManager:
    """
    Manages signal connections between different components of the application,
    ensuring seamless communication for events like login, logout, and token refresh.
    """
    def __init__(self, session_view: SessionViewModel, app_status: AppState,
                 event_manager: CentralQueueManager, session_client: SessionClient,
                 user_manager: UserManager) -> None:
        """
        Initialize the SignalConnectionManager with the required components.

        Args:
            session_view (SessionViewModel): The view responsible for session-related UI interactions.
            app_status (AppState): Manages the application's current status or state.
            event_manager (CentralQueueManager): Handles the task queue and signal/event processing.
            session_client (SessionClient): Manages API requests and session operations.
            user_manager (UserManager): Handles user-specific operations like login and logout.
        """
        self.session_view = session_view
        self.app_status = app_status
        self.event_manager = event_manager
        self.session_client = session_client
        self.user_manager = user_manager

    def connect_signals(self)-> None:
        """
        Establishes connections between signals and their respective slots.
        
        This ensures that events are properly communicated and handled across the 
        different components of the application.
        """
        # Application state signals
        self.session_view.appStateChanged.connect(self.app_status.set_state)
    
        # Event manager signals for task handling
        self.session_view.addEvent.connect(self.event_manager.add_task)
        self.session_client.addEvent.connect(self.event_manager.add_task)
        self.user_manager.addEvent.connect(self.event_manager.add_task)

        # Event manager signals for session operations
        self.event_manager.send_login_event.connect(self.session_client.send_login_request)
        self.event_manager.send_refresh_token_event.connect(self.session_client.send_refresh_token_request)
        self.event_manager.send_logout_event.connect(self.session_client.send_logout_request)
        self.event_manager.handle_login_event.connect(self.user_manager.login)
        self.event_manager.set_secret_key.connect(self.user_manager.generate_secret_key)
        self.event_manager.handle_refresh_token_event.connect(self.user_manager.refresh_token)
        self.event_manager.logout_get_token_event.connect(self.user_manager.logout_get_token)
        self.event_manager.handle_logout_event.connect(self.user_manager.logout)
        
        # UI feedback signals
        self.event_manager.logout_success_event.connect(self.session_view.logout_success)
        self.event_manager.login_failed_event.connect(self.session_view.login_failed)
        self.event_manager.login_success_event.connect(self.session_view.login_success)

        
        
        # Exception handling signals
        self.event_manager.handle_exception_event.connect(self.session_view.cqm_process_exception)
        self.event_manager.handle_exception_event.connect(self.user_manager.cqm_process_exception)
        self.event_manager.handle_exception_event.connect(self.session_client.cqm_process_exception)

        