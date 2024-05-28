from ..utils.db import get_database
from ..utils.main import get_password_hash
from pymongo import ReturnDocument
from bson import ObjectId

db = get_database()
collection = db["users"]

def get_users():
    user_list = collection.find()
    return list(user_list)

async def create_user(user: dict):
    try:
        if user["account_type"] == "GOOGLE":
            return collection.insert_one(user).inserted_id
    except KeyError:
        pass
    try:
        user["password"] = get_password_hash(user["password"])
    except KeyError:
        raise ValueError("password is required")
    return collection.insert_one(user).inserted_id

async def get_user_by_username(username: str):
    user = collection.find_one({"username": username})
    return user

async def get_user_by_email(email: str):
    user = collection.find_one({"email": email})
    return user

async def get_user_by_id(id: str):
    user = collection.find_one({"_id": ObjectId(id)})
    return user

async def get_google_user_by_access_token(access_token: str):
    user = collection.find_one({"token.access_token": access_token})
    return user

async def get_google_user_by_refresh_token(refresh_token: str):
    user = collection.find_one({"token.refresh_token": refresh_token})
    return user

async def update_refresh_token(username: str, refresh_token: str | None, new=False):
    return collection.find_one_and_update({"username": username}, {"$set": {"refresh_token": refresh_token}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_google_token(username: str, google_token: dict | None, new=False):
    return collection.find_one_and_update({"username": username}, {"$set": {"token": google_token}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_password(username: str, password: str, new=False):
    hashed_password = get_password_hash(password)
    return collection.find_one_and_update({"username": username}, {"$set": {"password": hashed_password}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_full_name(username: str, full_name: str, new=False):
    return collection.find_one_and_update({"username": username}, {"$set": {"full_name": full_name}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_avatar(username: str, avatar: dict, new=False):
    return collection.find_one_and_update({"username": username}, {"$set": {"avatar": avatar}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_cover_image(username: str, cover_image: dict, new=False):
    return collection.find_one_and_update({"username": username}, {"$set": {"cover_image": cover_image}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def delete_user(username: str):
    return collection.delete_one({"username": username})

