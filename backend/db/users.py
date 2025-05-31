from ..utils.db import get_database
from ..utils.main import get_password_hash
from pymongo.asynchronous.database import AsyncDatabase
from pymongo import ReturnDocument, ASCENDING
from pymongo.errors import OperationFailure
from bson import ObjectId

# db = get_database()

async def ensure_username_email_index(db: AsyncDatabase):
    existing_indexes = [index["name"] async for index in await db.users.list_indexes()]
    if "username_1" and "email_1" not in existing_indexes:
        try:
            await db.users.create_index([("username", ASCENDING)], name="username_1", unique=True)
            print("✅ Created index on 'username'")
        except OperationFailure as e:
            print(f"⚠️ Index creation failed: {e}")
    if "email_1" not in existing_indexes:
        try:
            await db.users.create_index([("email", ASCENDING)], name="email_1", unique=True)
            print("✅ Created index on 'email'")
        except OperationFailure as e:
            print(f"⚠️ Index creation failed: {e}")
    

async def get_users(db: AsyncDatabase):
    user_list = []
    async for user in db.users.find():
        user_list.append(user)
    return user_list

async def create_user(user: dict, db: AsyncDatabase):
    try:
        if user["account_type"] == "GOOGLE":
            res = await db.users.insert_one(user)
            return res.inserted_id
    except KeyError:
        pass
    try:
        user["password"] = get_password_hash(user["password"])
    except KeyError:
        raise ValueError("password is required")
    res = await db.users.insert_one(user)
    return res.inserted_id

async def get_user_by_username(username: str, db: AsyncDatabase):
    user = await db.users.find_one({"username": username})
    return user

async def get_user_by_email(email: str, db: AsyncDatabase):
    user = await db.users.find_one({"email": email})
    return user

async def get_user_by_id(id: str, db: AsyncDatabase):
    user = await db.users.find_one({"_id": ObjectId(id)})
    return user

async def get_google_user_by_access_token(access_token: str, db: AsyncDatabase):
    user = await db.users.find_one({"token.access_token": access_token})
    return user

async def get_google_user_by_refresh_token(refresh_token: str, db: AsyncDatabase):
    user = await db.users.find_one({"token.refresh_token": refresh_token})
    return user

async def update_refresh_token(username: str, refresh_token: str | None, db: AsyncDatabase, new=False):
    return await db.users.find_one_and_update({"username": username}, {"$set": {"refresh_token": refresh_token}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_google_token(username: str, google_token: dict | None, db: AsyncDatabase, new=False):
    return await db.users.find_one_and_update({"username": username}, {"$set": {"token": google_token}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_password(username: str, password: str, db: AsyncDatabase, new=False):
    hashed_password = get_password_hash(password)
    return await db.users.find_one_and_update({"username": username}, {"$set": {"password": hashed_password}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_full_name(username: str, full_name: str, db: AsyncDatabase, new=False):
    return await db.users.find_one_and_update({"username": username}, {"$set": {"full_name": full_name}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_avatar(username: str, avatar: dict, db: AsyncDatabase, new=False):
    return await db.users.find_one_and_update({"username": username}, {"$set": {"avatar": avatar}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_cover_image(username: str, cover_image: dict, db: AsyncDatabase, new=False):
    return await db.users.find_one_and_update({"username": username}, {"$set": {"cover_image": cover_image}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def update_listing(username: str, listing_id: str, db: AsyncDatabase, new=False):
    return await db.users.find_one_and_update({"username": username}, {"$push": {"listings": listing_id}}, return_document=ReturnDocument.AFTER if new else ReturnDocument.BEFORE)

async def delete_user(username: str, db: AsyncDatabase):
    return await db.users.delete_one({"username": username})

