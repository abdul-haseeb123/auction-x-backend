import os
import pytest
from datetime import datetime
from pydantic import EmailStr
from ..schemas.users import User, GoogleToken, GoogleUser, UserCreate
import unittest.mock as mock
from pymongo import AsyncMongoClient

def test_user_creation_minimum():
    user_data = {
        "full_name": "John Doe",
        "username": "john_doe",
        "email": "john@example.com",
    }
    user = User(**user_data)
    assert user.full_name == "John Doe"
    assert user.username == "john_doe"
    assert user.email == "john@example.com"
    assert user.email_verified == False
    assert user.account_type == "EMAIL"


def test_user_creation_complete():
    user_data = {
        "_id": "123",
        "full_name": "John Doe",
        "username": "john_doe",
        "email": "john@example.com",
        "email_verified": True,
        "avatar": "avatar.jpg",
        "cover_image": "cover.jpg",
        "account_type": "EMAIL"
    }
    user = User(**user_data)
    assert user.id == "123"
    assert user.avatar == "avatar.jpg"
    assert user.cover_image == "cover.jpg"

def test_google_token():
    current_dt = datetime.now()
    token_data = {
        "access_token": "access123",
        "refresh_token": "refresh123",
        "expires_at": current_dt
    }
    token = GoogleToken(**token_data)
    assert token.access_token == "access123"
    assert token.refresh_token == "refresh123"
    assert token.expires_at == current_dt


def test_user_create_validation():
    with pytest.raises(ValueError):
        UserCreate(
            full_name="John Doe",
            username="john doe",  # contains space
            email="john@example.com",
            password="password123"
        )
    
    with pytest.raises(ValueError):
        UserCreate(
            full_name="",  # empty name
            username="johndoe",
            email="john@example.com",
            password="password123"
        )

    user = UserCreate(
        full_name="john doe",  # should be titled
        username="johndoe",
        email="john@example.com",
        password="password123"
    )
    assert user.full_name == "John Doe"

@pytest.mark.asyncio
@mock.patch("backend.db.users.create_user")
async def test_user_create_save(mock_create_user):
    # Mock the create_user function
    mock_create_user.return_value = "new_user_id"
    client = AsyncMongoClient(os.environ.get("MONGODB_URI", "mongodb://localhost:27017/"))
    db = client[os.environ.get("TEST_DB_NAME", "test-commerce")]
    user = UserCreate(
        full_name="John Doe",
        username="johndoe",
        email="john@example.com",
        password="password123"
    )
    saved_user = await user.save(db)
    await client.close()
    
    assert saved_user.id == "new_user_id"
    assert saved_user.full_name == "John Doe"
    mock_create_user.assert_called_once()