from pymongo import AsyncMongoClient
import os

client = AsyncMongoClient(os.environ.get("MONGODB_URI", "mongodb://localhost:27017/"))


def get_db():
    db = client[os.environ.get("DB_NAME", "commerce")]
    yield db
