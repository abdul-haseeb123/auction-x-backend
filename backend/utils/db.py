from pymongo import MongoClient
import os

def get_database():
    client = MongoClient(os.environ.get("MONGODB_URI", "mongodb://localhost:27017/"))
    db = client[os.environ.get("DB_NAME", "commerce")]

    return db


