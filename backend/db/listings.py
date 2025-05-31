from ..utils.db import get_database
from . import users
from bson import ObjectId
from pymongo import ReturnDocument, ASCENDING
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import OperationFailure


# db.listings.create_index("slug", unique=True)

async def ensure_slug_index(db: AsyncDatabase):
    existing_indexes = [index["name"] async for index in await db.listings.list_indexes()]
    if "slug_1" not in existing_indexes:
        try:
            await db.listings.create_index([("slug", ASCENDING)], name="slug_1", unique=True)
            print("✅ Created index on 'slug'")
        except OperationFailure as e:
            print(f"⚠️ Index creation failed: {e}")

async def get_listings(db: AsyncDatabase):
    listing_list = []
    db.listings.list_indexes()
    async for listing in db.listings.find():
        listing_list.append(listing)
    return listing_list

async def create_listing(listing: dict, db: AsyncDatabase):
    try:
        owner_id = listing["owner"]
        owner = await users.get_user_by_id(owner_id, db)
        if not owner:
            raise ValueError("owner does not exist")
        result = await db.listings.insert_one(listing)
        try:
            await users.update_listing(owner["username"], result.inserted_id, db)
        except Exception as e:
            await db.listings.delete_one({"_id": result.inserted_id})
            raise e
    except KeyError:
        raise ValueError("owner is required")
    return result.inserted_id

async def get_listing_by_slug(slug: str, db: AsyncDatabase):
    listing = await db.listings.find_one({"slug": slug})
    return listing

async def update_listing(slug: str, data: dict, db: AsyncDatabase, new: bool = False):
    return await db.listings.find_one_and_update({"slug": slug}, {"$set": data}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_listing_bid(slug: str, data: dict, db: AsyncDatabase, new:bool = False):
    return await db.listings.find_one_and_update({"slug": slug}, {"$push": {"bids": data}, "$set": {"current_bid": data["amount"]}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)
    

async def delete_listing(username: str, listing_slug: str, db: AsyncDatabase):
    listing = await db.listings.find_one({"slug": listing_slug})
    owner = await users.get_user_by_username(username, db)
    if str(listing["owner"]) != str(owner["_id"]):
        raise ValueError("listing does not belong to user")
    return await db.listings.delete_one({"slug": listing_slug})
