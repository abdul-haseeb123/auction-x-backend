import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from ..dependencies.db import get_db
from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase
from ..main import app
import os
from contextlib import asynccontextmanager
from ..db.listings import ensure_slug_index
from ..db.users import ensure_username_email_index
from ..utils.main import delete_image
from fastapi import FastAPI



@pytest_asyncio.fixture(name="test_db")
async def get_test_db():
    client = AsyncMongoClient(os.environ.get("MONGODB_URI", "mongodb://localhost:27017/"))
    db = client["test-commerce"]
    await ensure_slug_index(db)
    await ensure_username_email_index(db)
    yield db
    await client.close()

@pytest_asyncio.fixture(name="test_client")
async def get_test_client(test_db):
    def get_test_db():
        return test_db
    app.dependency_overrides[get_db] = get_test_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://127.0.0.1:8000/api/v1"
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_get_users(test_db:AsyncDatabase, test_client):
    # Insert test data into the test database
    users_list = [
        {
            "username": "alice",
            "full_name": "Alice",
            "avatar": None,
            "cover_image": None,
            "email": "alice@example.com",
            "email_verified": False,
            "password": "hashedpassword1",
            "account_type": "EMAIL"
        }, 
        {
            "username": "bob",
            "full_name": "Bob",
            "avatar": None,
            "cover_image": None,
            "email": "bob@example.com",
            "email_verified": False,
            "password": "hashedpassword2",
            "account_type": "EMAIL"
        }, 
        {
            "username": "charlie",
            "full_name": "Charlie",
            "avatar": None,
            "cover_image": None,
            "email": "charlie@example.com",
            "email_verified": False,
            "password": "hashedpassword2",
            "account_type": "EMAIL"
        }
    ]
    await test_db.users.insert_many(users_list)

    response = await test_client.get("/users/")      
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert isinstance(data["data"], list)
    assert len(data["data"]) == 3
    assert isinstance(response.json(), dict)

    await test_db.users.delete_many({})  # Clean up test data



@pytest.mark.asyncio
async def test_register_user(test_client: AsyncClient):
    response = await test_client.post("/users/", data={
        "full_name": "Test User 1",
        "username": "testuser1",
        "email": "testuser1@example.com",
        "password": "testpassword1",  
    })
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser1"


@pytest.mark.asyncio
async def test_register_user_with_existing_username(test_client: AsyncClient, test_db: AsyncDatabase):
    # First, register a user with the username "existinguser
    response = await test_client.post("/users/", data={
        "full_name": "Test User 2",
        "username": "testuser1",
        "email": "testuser2@example.com",
        "password": "testpassword2",
    })
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Username or email already exists"

    await test_db.users.delete_one({"username": "testuser1"})  # Clean up test data

@pytest.mark.asyncio
async def test_register_user_with_existing_email(test_client: AsyncClient, test_db: AsyncDatabase):
    # First, register a user with the email "
    response = await test_client.post("/users/", data={
        "full_name": "Test User 3",
        "username": "testuser3",
        "email": "testuser3@example.com",
        "password": "testpassword3",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "User registered successfully"
    assert "username" in data["data"] and data["data"]["username"] == "testuser3"

    # Now, try to register another user with the same email
    response = await test_client.post("/users/", data={
        "full_name": "Test User 4",
        "username": "testuser4",
        "email": "testuser3@example.com",
        "password": "testpassword4",
    })
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Username or email already exists"

    await test_db.users.delete_one({"username": "testuser3"})  # Clean up test data

@pytest.mark.asyncio
async def test_register_user_with_invalid_email(test_client: AsyncClient):
    response = await test_client.post("/users/", data={
        "full_name": "Test User 5",
        "username": "testuser5",
        "email": "invalid-email",
        "password": "testpassword5",
    })
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_register_user_with_missing_fields(test_client: AsyncClient):
    response = await test_client.post("/users/", data={
        "full_name": "Test User 6",
        "username": "testuser6",
        # Missing email and password
    })
    assert response.status_code == 400

@pytest.mark.asyncio
async def test_register_user_with_invalid_avatar(test_client: AsyncClient):
    response = await test_client.post("/users/", data={
        "full_name": "Test User 7",
        "username": "testuser7",
        "email": "testuser7@example.com",
        "password": "testpassword7",
    }, files={
        "avatar": ("test.txt", open("assets/test/test.txt", "rb"), "text/plain")
    })

    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Avatar must be an image file"

    response = await test_client.post("/users/", data={
        "full_name": "Test User 7",
        "username": "testuser7",
        "email": "testuser7@example.com",
        "password": "testpassword7",
    }, files={
        "avatar": ("test.txt", open("assets/test/test.txt", "rb"), "image/avif")
    })
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Avatar must be an image file"

    response = await test_client.post("/users/", data={
        "full_name": "Test User 7",
        "username": "testuser7",
        "email": "testuser7@example.com",
        "password": "testpassword7",
    }, files={
        "avatar": ("test.jpeg", open("assets/test/test.txt", "rb"), "image/avif")
    })
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Avatar must be an image file"

@pytest.mark.asyncio
async def test_register_user_with_invalid_cover_image(test_client: AsyncClient):
    response = await test_client.post("/users/", data={
        "full_name": "Test User 8",
        "username": "testuser8",
        "email": "testuser8@example.com",
        "password": "testpassword8",
    }, files={
        "cover_image": ("test.txt", open("assets/test/test.txt", "rb"), "text/plain")
    })

    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Cover image must be an image file"

    response = await test_client.post("/users/", data={
        "full_name": "Test User 8",
        "username": "testuser8",
        "email": "testuser8@example.com",
        "password": "testpassword8",
    }, files={
        "cover_image": ("test.txt", open("assets/test/test.txt", "rb"), "image/avif")
    })
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Cover image must be an image file"

    response = await test_client.post("/users/", data={
        "full_name": "Test User 8",
        "username": "testuser8",
        "email": "testuser8@example.com",
        "password": "testpassword8",
    }, files={
        "cover_image": ("test.jpeg", open("assets/test/test.txt", "rb"), "image/avif")
    })
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Cover image must be an image file"

@pytest.mark.asyncio
async def test_create_user_with_avatar_and_cover_image(test_client: AsyncClient, test_db: AsyncDatabase):
    response = await test_client.post("/users/", data={
        "full_name": "Test User 9",
        "username": "testuser9",
        "email": "testuser9@example.com",
        "password": "testpassword9",
    }, files={
        "avatar": ("avatar.jpg", open("assets/test/avatar.avif", "rb"), "image/avif"),
        "cover_image": ("cover.jpg", open("assets/test/cover.jpg", "rb"), "image/jpeg")
    })

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser9"
    assert data["data"]["avatar"] is not None
    assert data["data"]["cover_image"] is not None
    assert data["data"]["avatar"]["url"] is not None
    assert data["data"]["cover_image"]["url"] is not None
    assert data["data"]["avatar"]["secure_url"] is not None
    assert data["data"]["cover_image"]["secure_url"] is not None
    assert data["data"]["avatar"]["resource_type"] == "image"  
    assert data["data"]["cover_image"]["resource_type"] == "image"

    # Clean up the test user
    avatar = data["data"]["avatar"]
    cover_image = data["data"]["cover_image"]

    await delete_image(avatar["public_id"])
    await delete_image(cover_image["public_id"])

    await test_db.users.delete_one({"username": "testuser9"})  # Clean up test data

@pytest.mark.asyncio
async def test_login_logout_user(test_client: AsyncClient, test_db: AsyncDatabase):
    # First, register a user
    response = await test_client.post("/users/", data={
        "full_name": "Test User 10",
        "username": "testuser10",
        "email": "testuser10@example.com",
        "password": "testpassword10",
    })
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser10"

    # Now, log in the user
    response = await test_client.post("/users/login", data={
        "username": "testuser10",
        "password": "testpassword10"
    })

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User logged in successfully"
    assert data["data"]["user"]["username"] == "testuser10"

    # Check if the access_token, refresh_token cookie is set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

    # Store the cookies in the client for future requests
    test_client.cookies.set("access_token", response.cookies.get("access_token"))
    test_client.cookies.set("refresh_token", response.cookies.get("refresh_token"))
    # Now, log out the user
    response = await test_client.post("/users/logout")
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "message" in data
    assert data["message"] == "User logged out successfully"
    assert "access_token" not in response.cookies
    assert "refresh_token" not in response.cookies
    # Clean up the test user
    await test_db.users.delete_one({"username": "testuser10"})


