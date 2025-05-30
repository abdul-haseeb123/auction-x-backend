import pytest
import pytest_asyncio
from bson import ObjectId
import backend.db.users as users
from pymongo import AsyncMongoClient
import os
from ..schemas.images import Image

@pytest_asyncio.fixture(name="test_db")
async def get_test_db():
    client = AsyncMongoClient(os.environ.get("MONGODB_URI", "mongodb://localhost:27017/"))
    db_name = os.environ.get("test_db_NAME", "test-commerce")
    db = client[db_name]
    try:
        yield db
    finally:
        await client.close()

@pytest.fixture(name="avatar")
def get_example_avatar():
    return Image(
        asset_id="807f172fcb44ca867c1239471c0774b",
        public_id="auction_x/bydsawxwptlpgzh7herp",
        width=1920,
        height=1080,
        resource_type="image",
        tags=[],
        url="http://res.cloudinary.com/auction_x/image/upload/v1633661234/auction_x/bydsawxwptlpgzh7herp.jpg",
        secure_url="https://res.cloudinary.com/auction_x/image/upload/v1633661234/auction_x/bydsawxwptlpgzh7herp.jpg"
    ).model_dump()


@pytest.mark.asyncio
async def test_create_and_get_user(test_db):
    user_data = {
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "testpassword",
        "account_type": "EMAIL"
    }
    inserted_id = await users.create_user(user_data.copy(), test_db)
    assert inserted_id is not None

    user = await users.get_user_by_username("testuser", test_db)
    assert user is not None
    assert user["username"] == "testuser"

    user_by_email = await users.get_user_by_email("testuser@example.com", test_db)
    assert user_by_email is not None
    assert user_by_email["email"] == "testuser@example.com"

    user_by_id = await users.get_user_by_id(str(user["_id"]), test_db)
    assert user_by_id is not None
    assert user_by_id["username"] == "testuser"

    await users.delete_user(user_by_id["username"], test_db)

@pytest.mark.asyncio
async def test_update_and_delete_user(test_db, avatar):
    user_data = {
        "username": "updateuser",
        "full_name": "Update User Name",
        "email": "updateuser@example.com",
        "password": "updatepassword",
        "account_type": "LOCAL"
    }
    await users.create_user(user_data.copy(), test_db)

    updated = await users.update_full_name("updateuser", "Updated Name", test_db, new=True)
    assert updated is not None
    assert updated["full_name"] == "Updated Name"

    await users.update_password("updateuser", "newpassword", test_db)
    updated_user = await users.get_user_by_username("updateuser", test_db)
    assert updated_user is not None
    assert "password" in updated_user

    updated = await users.update_avatar("updateuser", avatar, test_db, True)
    updated = await users.update_cover_image("updateuser", avatar, test_db, True)
    assert "avatar" in updated
    assert "cover_image" in updated


    result = await users.delete_user("updateuser", test_db)
    assert result.deleted_count == 1

@pytest.mark.asyncio
async def test_create_google_user_and_tokens(test_db):
    user_data = {
        "username": "googleuser",
        "full_name": "Google User",
        "email": "googleuser@example.com",
        "account_type": "GOOGLE",
        "token": {
            "access_token": "access123",
            "refresh_token": "refresh123"
        }
    }
    await users.create_user(user_data.copy(), test_db)

    google_user = await users.get_google_user_by_access_token("access123", test_db)
    assert google_user is not None
    assert google_user["username"] == "googleuser"

    google_user_by_refresh = await users.get_google_user_by_refresh_token("refresh123", test_db)
    assert google_user_by_refresh is not None
    assert google_user_by_refresh["username"] == "googleuser"

    await users.update_google_token("googleuser", {"access_token": "access456", "refresh_token": "refresh456"}, test_db)
    updated_user = await users.get_user_by_username("googleuser", test_db)
    assert updated_user["token"]["access_token"] == "access456"

    await users.delete_user("googleuser", test_db)