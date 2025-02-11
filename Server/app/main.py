from fastapi import FastAPI
from services.session_service import SessionService
from api.stream_screen import StreamRouter
from middleware.middleware import ConnectionLimiterMiddleware
from config import Config
from contextlib import asynccontextmanager
import redis.asyncio as redis
from redis.exceptions import ConnectionError
import os
import signal

import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages the application's lifespan, including initialization and shutdown procedures.
    
    This function handles:
    - Initializing the session service.
    - Connecting to Redis and handling potential connection errors.
    - Ensuring a session is created and maintained.
    - Setting up the stream router and registering routes.
    - Gracefully shutting down services when the application stops.
    
    Args:
        app (FastAPI): The FastAPI application instance.
    
    Yields:
        None: Allows the application to run within the lifespan context.
    """
    logger.info("Starting application...")
    
    # Initialize session service
    app.state.session_service = SessionService()
    
     # Establish Redis connection
    app.state.redis = await redis.from_url(Config.REDIS_URL)
    try:
        redis_status = await app.state.redis.ping()
        logger.info(f"Redis connection established: {redis_status}")
    except ConnectionError as e:
        logger.error(f"Redis connection error arise: {e}")
        await app.state.session_service.session_client.close_session()
        os.kill(os.getpid(), signal.SIGTERM)
 
    # Ensure Redis key existence for connection tracking
    if await app.state.redis.exists(Config.CONNECTION_COUNT_KEY) >= 0:
        logger.info("Connection count key does not exist. Initializing to 0.")
        await app.state.redis.set(Config.CONNECTION_COUNT_KEY, 0)
     
    # Initialize StreamRouter and start a session   
    app.state.stream_router = StreamRouter(app.state)
    await app.state.stream_router.session_service.session_client.create_session()

    # Include routers
    app.include_router(app.state.stream_router.router)
    
    # Notify server availability
    await app.state.session_service.server_available(Config.SERVER_NAME)
    
    yield
    
    # Application shutdown procedures
    logger.info("Application is shutting down...")
    await app.state.session_service.server_available(Config.SERVER_NAME,False)
    await app.state.redis.close()
    await app.state.session_service.session_client.close_session()
    await app.state.stream_router.session_service.session_client.close_session()

# Create FastAPI application with lifespan management
app = FastAPI(lifespan=lifespan)

# Attach HTTP middleware for connection limiting
app.middleware("http")(ConnectionLimiterMiddleware(app.state))

if __name__ == "__main__":
    import uvicorn
    uv_cfg = uvicorn.Config(
        "main:app",
        host="127.0.0.1",
        port=8000,
        log_level="debug",
        timeout_graceful_shutdown=20,
    )
    
    server = uvicorn.Server(config=uv_cfg)
    server.run()



