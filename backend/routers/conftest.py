import pytest_asyncio
from beanie import init_beanie
from httpx import ASGITransport, AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient

from ..config import settings
from ..main import app
from ..schemas.users import GoogleUser, LocalUser, User


@pytest_asyncio.fixture(name="test_client")
async def get_test_client():
    cli = AsyncIOMotorClient(settings.mongodb_uri)
    await init_beanie(
        database=cli[settings.test_db_name],
        document_models=[LocalUser, GoogleUser, User],
    )
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://127.0.0.1:8000/api/v1",
    ) as client:
        yield client
