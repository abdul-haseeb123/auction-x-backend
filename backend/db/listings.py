from ..utils.db import get_database
from . import users
from bson import ObjectId
from pymongo import ReturnDocument

db = get_database()
collection = db["listings"]

collection.create_index("slug", unique=True)

async def get_listings():
    listing_list = collection.find()
    return list(listing_list)

async def create_listing(listing: dict):
    try:
        owner_id = listing["owner"]
        owner = await users.get_user_by_id(owner_id)
        if not owner:
            raise ValueError("owner does not exist")
        result = collection.insert_one(listing)
        try:
            await users.update_listing(owner["username"], result.inserted_id)
        except Exception as e:
            collection.delete_one({"_id": result.inserted_id})
            raise e
    except KeyError:
        raise ValueError("owner is required")
    return result.inserted_id

async def get_listing_by_slug(slug: str):
    listing = collection.find_one({"slug": slug})
    return listing

async def update_listing(slug: str, data: dict, new: bool = False):
    return collection.find_one_and_update({"slug": slug}, {"$set": data}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_listing_bid(slug: str, data: dict, new:bool = False):
    return collection.find_one_and_update({"slug": slug}, {"$push": {"bids": data}, "$set": {"current_bid": data["amount"]}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)
    

async def delete_listing(username: str, listing_slug: str):
    listing = collection.find_one({"slug": listing_slug})
    owner = await users.get_user_by_username(username)
    if str(listing["owner"]) != str(owner["_id"]):
        raise ValueError("listing does not belong to user")
    return collection.delete_one({"slug": listing_slug})
