from app.database.session_db_manager import SessionDBManager

import logging


logger = logging.getLogger(__name__)

class SessionManager():
    def __init__(self):
        super().__init__()
        self._sesion_db_manager = SessionDBManager()

    def fetch_session(self, token):
        pass

    def save_session(self, session_data):
        pass

    def clear_session(self):
        pass

    def close_session(self, token):
        pass

    def start_refresh_timer(self):
        pass
    
    def stop_refresh_timer(self):
        pass