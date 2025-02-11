import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from api.stream_screen import StreamRouter
from fastapi.testclient import TestClient
from fastapi import FastAPI, status
import asyncio
import logging

logger = logging.getLogger(__name__)

class StreamRouterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mock_state = AsyncMock()
        self.router = StreamRouter(self.mock_state)
        self.mock_video_service = MagicMock()
        self.mock_session_service = AsyncMock()
        self.router.video_service = self.mock_video_service
        self.router.session_service = self.mock_session_service
        
        self.app = FastAPI()
        self.app.include_router(self.router.router)
        
        self.client = TestClient(self.app)
        
    async def async_frame_generator(self):
        logger.info("start async_frame_generator")
        try:
            for frame in [b'frame1', b'frame2']:
                yield frame
                await asyncio.sleep(0.02)
        except asyncio.CancelledError:
            logger.info("Frame stream canceled. Decreasing connection count.")
            
        
    async def test_video_feed_success(self):
        """Test successful video feed request."""
        logger.info("Started: test_video_feed_success")
        self.mock_session_service.verify_session.return_value = True
        self.mock_video_service.frame_generator.return_value = self.async_frame_generator()

        headers = {"Authorization": "Bearer valid_token"}
        response = self.client.get("/video", headers=headers)

        assert response.status_code == 200
        assert response.headers["content-type"] == "multipart/x-mixed-replace; boundary=frame"

        logger.info("Test Passed: test_video_feed_success")
        
    async def test_video_feed_unauthorized(self):
        """Test unauthorized access to video feed."""
        logger.info("Started: test_video_feed_unauthorized")
        
        self.mock_session_service.verify_session.return_value = False
        
        response = self.client.get("/video", headers={"Authorization": "Bearer invalid_token"})
    
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Unauthorized"
        
        logger.info("Test Passed: test_video_feed_unauthorized")

        
    @patch("api.stream_screen.base64.b64encode", side_effect=ValueError("Encoding error"))
    def test_video_feed_value_error(self, mock_b64encode):
        """Test ValueError handling in video feed endpoint."""
        logger.info("Started: test_video_feed_value_error")
        
        response = self.client.get("/video", headers={"Authorization": "Bearer valid_token"})
    
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Encoding error" in response.json()["detail"]
        
        logger.info("Test Passed: test_video_feed_value_error")
        

    def test_video_feed_internal_server_error(self):
        """Test internal server error handling."""
        logger.info("Started: test_video_feed_internal_server_error")
        
        self.mock_session_service.verify_session.return_value = True
        self.mock_video_service.frame_generator.side_effect = Exception("testException")
        response = self.client.get("/video", headers={"Authorization": "Bearer valid_token"})
        
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert response.json()["detail"] == "Internal Server Error"
        
        logger.info("Test Passed: test_video_feed_internal_server_error")
        