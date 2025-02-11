# Video streaming logic


from fastapi import APIRouter, Header, Query, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi import Request
from services.video_service import VideoService
from services.session_service import SessionService
import base64
import logging


logger = logging.getLogger(__name__) 


class StreamRouter:
    """
    Router for handling video streaming requests.

    This class sets up API routes for streaming video and manages session verification
    before allowing access to the video feed.

    Args:
        state (object): The application state, passed to video service initialization.
    """
    def __init__(self, state) -> None:
        """
        Initializes the StreamRouter with the necessary services and API routes.

        Args:
            state (object): The application state, used for initializing services.
        """
        self.router = APIRouter()
        self.video_service = VideoService(state)
        self.session_service = SessionService()

        self.router.add_api_route("/video", self.video_feed, methods=["GET"])
        self.router.add_event_handler("shutdown", self.shutdown_event)
        
        logger.info("StreamRouter initialized and API routes registered.")

    async def video_feed(
        self,
        request: Request,
        width: int = Query(640, description="Szerokość wideo"),
        height: int = Query(480, description="Wysokość wideo"),
        monitor: int = Query(0, description="Indeks monitora"),
        authorization: str = Header(..., description="Authorization token"),
    ) -> StreamingResponse:
        """
        Handles video streaming requests.

        This endpoint verifies the session before streaming video frames.
        The request must include an authorization token in the header.

        Args:
            request (Request): The incoming HTTP request.
            width (int, optional): The width of the video. Defaults to 640.
            height (int, optional): The height of the video. Defaults to 480.
            monitor (int, optional): The monitor index for capturing video. Defaults to 0.
            authorization (str): The authorization token (Bearer Token).

        Returns:
            StreamingResponse: The video stream response if session verification is successful.

        Raises:
            HTTPException: If authentication fails (401), invalid input is provided (400),
                           or an internal server error occurs (500).
        """
        logger.info("Received request for video feed.")
        try:
            # Extract client host, request path, and method
            host = request.headers.get("X-Forwarded-For", request.client.host)
            path = request.url.path 
            body = await request.body()
            method = request.method
            token = authorization.replace("Bearer ", "").strip()
            encoded_body = base64.b64encode(body).decode()

            logger.info(f"Processing request: {method} {path} from {host}")
            logger.debug(f"Request body (base64-encoded): {encoded_body}")
            logger.debug(f"Authorization token received.")
            
            # Verify session
            is_verified = await self.session_service.verify_session(
                    token=token,
                    method=method,
                    path=path,
                    encode_body=encoded_body,
                    host=host
                )
            if not is_verified:
                logger.warning("Session verification failed. Unauthorized access attempt.")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
            
            logger.info("Session verified. Starting video stream.")
            return StreamingResponse(
                self.video_service.frame_generator(monitor, width, height),
                media_type="multipart/x-mixed-replace; boundary=frame"
                )
        
        except HTTPException as e:
            logger.warning(f"HTTPException occurred: {e.detail}")
            raise
        except ValueError as e:
            logger.error(f"ValueError: {e}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            logger.error(f"Exception: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")

    async def shutdown_event(self):
        """
        Handles application shutdown event.

        Releases video resources before shutting down the application.
        """
        logger.info("Shutdown event triggered. Releasing video resources.")
        self.video_service.release()
        logger.info("Video resources released successfully.")

