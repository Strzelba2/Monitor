from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from config.config import Config
import logging

logger = logging.getLogger(__name__)

engine = create_async_engine(Config.DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

async def init_db():
    """
    Initializes the database asynchronously by creating all necessary tables.
    """
    try:
        # Check if tables exist and create them if not
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialized successfully.")
    except OperationalError as e:
        logger.error(f"Database initialization failed: {e}")
        raise