from ..utils.db import get_database

db = get_database()
collection = db["listings"]

async def create_listing(listing: dict):
    return None
