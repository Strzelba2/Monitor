from fastapi import Request
from starlette.responses import JSONResponse
from config import Config
import asyncio
import logging

logger = logging.getLogger(__name__)

class ConnectionLimiterMiddleware:
    """
    Middleware to limit the number of concurrent connections using Redis.

    This middleware checks the current number of active connections stored in Redis
    and rejects new requests when the limit is exceeded.

    Args:
        state (object): The application state, which should contain a Redis instance.
    """
    def __init__(self, state) -> None:
        """
        Initializes the ConnectionLimiterMiddleware with the given application state.

        Args:
            state (object): The application state, which should include a Redis instance.
        """
        self.state = state
        logger.info("ConnectionLimiterMiddleware initialized.")
        
    @property
    def redis(self):
        """
        Retrieves the Redis instance from the application state.

        Returns:
            Redis: The Redis client instance.

        Raises:
            RuntimeError: If the Redis instance is not initialized in the state.
        """
        logger.debug("Retrieving Redis instance from state.")
        if not hasattr(self.state, "redis"):
            logger.error("Redis is not initialized in the application state.")
            raise RuntimeError("Redis is not initialized yet.")
        return self.state.redis

    async def __call__(self, request: Request, call_next) -> JSONResponse:
        """
        Middleware entry point to limit concurrent connections.

        Increments the active connection count in Redis. If the number of active connections
        exceeds the configured maximum, the request is rejected with a 503 response.
        Otherwise, the request is processed, and the connection count is decremented afterward.

        Args:
            request (Request): The incoming FastAPI request.
            call_next (Callable): The next middleware or endpoint handler in the pipeline.

        Returns:
            JSONResponse: The response from the next middleware or a 503 error response if
                          the connection limit is exceeded.
        """
        logger.info(f"Processing request: {request.url}")
        
        # Increment connection count
        current_connections = await self.redis.incr(Config.CONNECTION_COUNT_KEY)
        await asyncio.sleep(0.1)

        try:
            if current_connections > Config.MAX_CONNECTIONS:
                logger.warning("Too many connections. Rejecting request.")
                await self.redis.decr(Config.CONNECTION_COUNT_KEY)
                return JSONResponse(
                    status_code=503,
                    content={"detail": "Too many connections."},
                )
             
            logger.info("Request within connection limits. Passing to next handler.")   
            response = await call_next(request)
        except Exception as e:
            logger.error(f"Error while processing request: {e}")
            raise e
        finally:
            logger.info("Request processed and connection count updated.")

        return response