import pytest_asyncio
import os
from pymongo import AsyncMongoClient


@pytest_asyncio.fixture(name="test_db")
async def get_test_db():
    client = AsyncMongoClient(
        os.environ.get("MONGODB_URI", "mongodb://localhost:27017/")
    )
    db_name = os.environ.get("test_db_NAME", "test-commerce")
    db = client[db_name]
    try:
        yield db
    finally:
        await client.close()
