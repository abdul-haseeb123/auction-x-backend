from datetime import datetime, timedelta, timezone

import pytest
from freezegun import freeze_time
from httpx import AsyncClient

from ..schemas.users import LocalUser
from ..utils.main import delete_image


def get_test_user(idx):
    return LocalUser(
        full_name=f"Test User {idx}",
        username=f"testuser{idx}",
        email=f"testuser{idx}@example.com",
        password=f"testpassword{idx}",
    )


def get_test_data():
    return {
        "full_name": "Test User",
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "testpassword",
    }


@pytest.mark.asyncio
async def test_get_users(test_client):
    # Insert test data into the test database
    users_list = [get_test_user(i) for i in range(10)]
    await LocalUser.insert_many(users_list)
    response = await test_client.get("/users/")
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert isinstance(data["data"], list)
    assert len(data["data"]) == 10
    assert isinstance(response.json(), dict)

    await LocalUser.delete_all()  # Clean up test data


@pytest.mark.asyncio
async def test_register_user(test_client: AsyncClient):
    response = await test_client.post("/users/", data=get_test_data())
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser"
    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_register_user_with_existing_username(test_client: AsyncClient):
    response = await test_client.post("/users/", data=get_test_data())
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "User registered successfully"
    assert "username" in data["data"] and data["data"]["username"] == "testuser"

    response = await test_client.post(
        "/users/",
        data={
            "full_name": "Test User1",
            "username": "testuser",
            "email": "testuser1@example.com",
            "password": "testpassword1",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Username or email already exists"

    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_register_user_with_existing_email(test_client: AsyncClient):
    # First, register a user with the email "
    response = await test_client.post("/users/", data=get_test_data())
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "User registered successfully"
    assert "username" in data["data"] and data["data"]["username"] == "testuser"

    # Now, try to register another user with the same email
    response = await test_client.post(
        "/users/",
        data={
            "full_name": "Test User1",
            "username": "testuser1",
            "email": "testuser@example.com",
            "password": "testpassword1",
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Username or email already exists"

    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_register_user_with_invalid_email(test_client: AsyncClient):
    data = get_test_data()
    data["email"] = "invalid-email"
    response = await test_client.post(
        "/users/",
        data=data,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_register_user_with_missing_fields(test_client: AsyncClient):
    response = await test_client.post(
        "/users/",
        data={
            "full_name": "Test User",
            "username": "testuser",
            # Missing email and password
        },
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_register_user_with_invalid_avatar(test_client: AsyncClient):
    response = await test_client.post(
        "/users/",
        data=get_test_data(),
        files={
            "avatar": ("test.txt", open("assets/test/test.txt", "rb"), "text/plain")
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Avatar must be an image file"

    response = await test_client.post(
        "/users/",
        data=get_test_data(),
        files={
            "avatar": ("test.txt", open("assets/test/test.txt", "rb"), "image/avif")
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Avatar must be an image file"

    response = await test_client.post(
        "/users/",
        data=get_test_data(),
        files={
            "avatar": ("test.jpeg", open("assets/test/test.txt", "rb"), "image/avif")
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Avatar must be an image file"


@pytest.mark.asyncio
async def test_register_user_with_invalid_cover_image(test_client: AsyncClient):
    response = await test_client.post(
        "/users/",
        data=get_test_data(),
        files={
            "cover_image": (
                "test.txt",
                open("assets/test/test.txt", "rb"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Cover image must be an image file"

    response = await test_client.post(
        "/users/",
        data=get_test_data(),
        files={
            "cover_image": (
                "test.txt",
                open("assets/test/test.txt", "rb"),
                "image/avif",
            )
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Cover image must be an image file"

    response = await test_client.post(
        "/users/",
        data=get_test_data(),
        files={
            "cover_image": (
                "test.jpeg",
                open("assets/test/test.txt", "rb"),
                "image/avif",
            )
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Cover image must be an image file"


@pytest.mark.asyncio
async def test_create_user_with_avatar_and_cover_image(test_client: AsyncClient):
    response = await test_client.post(
        "/users/",
        data=get_test_data(),
        files={
            "avatar": (
                "avatar.jpg",
                open("assets/test/avatar.avif", "rb"),
                "image/avif",
            ),
            "cover_image": (
                "cover.jpg",
                open("assets/test/cover.jpg", "rb"),
                "image/jpeg",
            ),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser"
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

    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_login_logout_user(test_client: AsyncClient):
    # First, register a user
    response = await test_client.post("/users/", data=get_test_data())
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser"

    # Now, log in the user
    response = await test_client.post(
        "/users/login", data={"username": "testuser", "password": "testpassword"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User logged in successfully"
    assert data["data"]["user"]["username"] == "testuser"

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
    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_login_user_with_invalid_credentials(test_client: AsyncClient):
    response = await test_client.post(
        "/users/login",
        data={"username": "nonexistentuser", "password": "wrongpassword"},
    )
    assert response.status_code == 401
    data = response.json()
    assert data is not None
    assert "detail" in data
    assert data["detail"] == "Incorrect username or password"

    response = await test_client.post("/users/", data=get_test_data())

    response = await test_client.post(
        "/users/login", data={"username": "testuser", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    data = response.json()
    assert data is not None
    assert "detail" in data
    assert data["detail"] == "Incorrect username or password"

    response = await test_client.post(
        "/users/login", data={"username": "wrongusername", "password": "testpassword"}
    )
    assert response.status_code == 401
    data = response.json()
    assert data is not None
    assert "detail" in data
    assert data["detail"] == "Incorrect username or password"
    # Clean up the test user
    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_get_current_user(test_client: AsyncClient):
    # First, register a user
    response = await test_client.post("/users/", data=get_test_data())

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser"

    # Now, log in the user
    response = await test_client.post(
        "/users/login", data={"username": "testuser", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User logged in successfully"
    assert data["data"]["user"]["username"] == "testuser"
    # Check if the access_token, refresh_token cookie is set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

    # Store the cookies in the client for future requests
    test_client.cookies.set("access_token", response.cookies.get("access_token"))
    test_client.cookies.set("refresh_token", response.cookies.get("refresh_token"))
    # Now, get the current user
    response = await test_client.get("/users/current-user")
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert data["message"] == "User fetched successfully"
    assert "data" in data
    assert data["data"]["username"] == "testuser"
    assert data["data"]["email"] == "testuser@example.com"
    assert data["data"]["full_name"] == "Test User"
    assert "password" not in data["data"]  # Password should not be returned

    response = await test_client.post("/users/logout")
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "message" in data
    assert data["message"] == "User logged out successfully"
    assert "access_token" not in response.cookies
    assert "refresh_token" not in response.cookies

    # Clean up the test user
    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_get_current_user_without_login(test_client: AsyncClient):
    response = await test_client.get("/users/current-user")
    assert response.status_code == 401
    data = response.json()
    assert data is not None
    assert "detail" in data
    assert data["detail"] == "Could not validate credentials"


@pytest.mark.asyncio
async def test_login_update_user(test_client: AsyncClient):
    # First, register a user
    response = await test_client.post("/users/", data=get_test_data())
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser"

    # Now, log in the user
    response = await test_client.post(
        "/users/login", data={"username": "testuser", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User logged in successfully"
    assert data["data"]["user"]["username"] == "testuser"
    # Check if the access_token, refresh_token cookie is set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies
    # Store the cookies in the client for future requests
    test_client.cookies.set("access_token", response.cookies.get("access_token"))
    test_client.cookies.set("refresh_token", response.cookies.get("refresh_token"))
    # Now, update the user
    response = await test_client.put("/users/update-profile", json="Updated User")
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "Profile updated successfully"
    assert data["data"]["username"] == "testuser"
    assert data["data"]["full_name"] == "Updated User"

    # Now, update the user with an empty full_name
    response = await test_client.put("/users/update-profile", json="")
    assert response.status_code == 422
    data = response.json()
    assert data is not None

    await test_client.post("/users/logout")
    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_login_update_avatar(test_client: AsyncClient):
    # First, register a user
    response = await test_client.post("/users/", data=get_test_data())
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser"

    # Now, log in the user
    response = await test_client.post(
        "/users/login", data={"username": "testuser", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User logged in successfully"
    assert data["data"]["user"]["username"] == "testuser"

    # Check if the access_token, refresh_token cookie is set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies
    # Store the cookies in the client for future requests
    test_client.cookies.set("access_token", response.cookies.get("access_token"))
    test_client.cookies.set("refresh_token", response.cookies.get("refresh_token"))

    # Now, update the avatar
    response = await test_client.put(
        "/users/update-avatar",
        files={
            "avatar": ("avatar.jpg", open("assets/test/cover.jpg", "rb"), "image/jpeg")
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "Avatar updated successfully"
    assert data["data"]["username"] == "testuser"
    assert data["data"]["avatar"] is not None
    assert data["data"]["avatar"]["url"] is not None
    assert data["data"]["avatar"]["secure_url"] is not None
    assert data["data"]["avatar"]["resource_type"] == "image"

    # Now, update the avatar again and delete the previous one
    avatar_public_id = data["data"]["avatar"]["public_id"]
    response = await test_client.put(
        "/users/update-avatar",
        files={
            "avatar": (
                "avatar.jpg",
                open("assets/test/avatar.avif", "rb"),
                "image/avif",
            )
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "Avatar updated successfully"
    assert data["data"]["username"] == "testuser"
    assert data["data"]["avatar"] is not None
    assert data["data"]["avatar"]["url"] is not None
    assert data["data"]["avatar"]["secure_url"] is not None
    assert data["data"]["avatar"]["resource_type"] == "image"

    assert data["data"]["avatar"]["public_id"] != avatar_public_id, (
        "Avatar public ID should be different after update"
    )
    avatar_public_id = data["data"]["avatar"]["public_id"]
    # Clean up the previous avatar image

    # Now, update the avatar with an invalid file
    response = await test_client.put(
        "/users/update-avatar",
        files={
            "avatar": ("test.txt", open("assets/test/test.txt", "rb"), "text/plain")
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data is not None
    assert "detail" in data
    assert data["detail"] == "Avatar must be an image file"

    # Now, update the avatar with an invalid file type
    response = await test_client.put(
        "/users/update-avatar",
        files={
            "avatar": ("test.txt", open("assets/test/test.txt", "rb"), "image/avif")
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data is not None
    assert "detail" in data
    assert data["detail"] == "Avatar must be an image file"

    # Now, update the avatar with an invalid file type
    response = await test_client.put(
        "/users/update-avatar",
        files={
            "avatar": ("test.jpeg", open("assets/test/test.txt", "rb"), "image/avif")
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data is not None
    assert "detail" in data
    assert data["detail"] == "Avatar must be an image file"
    # Clean up the test user
    await delete_image(avatar_public_id)
    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_login_update_cover(test_client: AsyncClient):
    # First, register a user
    response = await test_client.post("/users/", data=get_test_data())
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser"

    # Now, log in the user
    response = await test_client.post(
        "/users/login", data={"username": "testuser", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User logged in successfully"
    assert data["data"]["user"]["username"] == "testuser"

    # Check if the access_token, refresh_token cookie is set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies
    # Store the cookies in the client for future requests
    test_client.cookies.set("access_token", response.cookies.get("access_token"))
    test_client.cookies.set("refresh_token", response.cookies.get("refresh_token"))

    # Now, update the cover image
    response = await test_client.put(
        "/users/update-cover-image",
        files={
            "cover_image": (
                "avatar.avif",
                open("assets/test/avatar.avif", "rb"),
                "image/avif",
            )
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "Cover image updated successfully"
    assert data["data"]["username"] == "testuser"
    assert data["data"]["cover_image"] is not None
    assert data["data"]["cover_image"]["url"] is not None
    assert data["data"]["cover_image"]["secure_url"] is not None
    assert data["data"]["cover_image"]["resource_type"] == "image"

    # Now, update the cover image again and delete the previous one
    cover_image_public_id = data["data"]["cover_image"]["public_id"]
    response = await test_client.put(
        "/users/update-cover-image",
        files={
            "cover_image": (
                "cover.jpg",
                open("assets/test/cover.jpg", "rb"),
                "image/jpeg",
            )
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "Cover image updated successfully"
    assert data["data"]["username"] == "testuser"
    assert data["data"]["cover_image"] is not None
    assert data["data"]["cover_image"]["url"] is not None
    assert data["data"]["cover_image"]["secure_url"] is not None
    assert data["data"]["cover_image"]["resource_type"] == "image"

    assert data["data"]["cover_image"]["public_id"] != cover_image_public_id, (
        "Cover image public ID should be different after update"
    )
    cover_image_public_id = data["data"]["cover_image"]["public_id"]
    # Clean up the previous cover image

    # Now, update the cover with an invalid file
    response = await test_client.put(
        "/users/update-cover-image",
        files={
            "cover_image": (
                "test.txt",
                open("assets/test/test.txt", "rb"),
                "text/plain",
            )
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data is not None
    assert "detail" in data
    assert data["detail"] == "Cover image must be an image file"

    # Now, update the cover with an invalid file type
    response = await test_client.put(
        "/users/update-cover-image",
        files={
            "cover_image": (
                "test.txt",
                open("assets/test/test.txt", "rb"),
                "image/avif",
            )
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data is not None
    assert "detail" in data
    assert data["detail"] == "Cover image must be an image file"

    # Now, update the cover with an invalid file type
    response = await test_client.put(
        "/users/update-cover-image",
        files={
            "cover_image": (
                "test.jpeg",
                open("assets/test/test.txt", "rb"),
                "image/avif",
            )
        },
    )
    assert response.status_code == 400
    data = response.json()
    assert data is not None
    assert "detail" in data
    assert data["detail"] == "Cover image must be an image file"
    # Clean up the test user
    await delete_image(cover_image_public_id)
    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_login_access_token(test_client: AsyncClient):
    response = await test_client.post("/users/", data=get_test_data())
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser"

    # Now, log in the user
    response = await test_client.post(
        "/users/login", data={"username": "testuser", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User logged in successfully"
    assert data["data"]["user"]["username"] == "testuser"
    # Check if the access_token, refresh_token cookie is set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies
    # Store the cookies in the client for future requests
    test_client.cookies.set("access_token", response.cookies.get("access_token"))
    test_client.cookies.set("refresh_token", response.cookies.get("refresh_token"))

    # Now, check the current user
    response = await test_client.get("/users/current-user")
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert data["message"] == "User fetched successfully"
    assert "data" in data
    assert data["data"]["username"] == "testuser"

    # Now, check the current user after 23 hours
    with freeze_time(datetime.now(timezone.utc) + timedelta(hours=23)):
        response = await test_client.get("/users/current-user")
        assert response.status_code == 200
        data = response.json()
        assert data is not None
        assert data["message"] == "User fetched successfully"
        assert "data" in data
        assert data["data"]["username"] == "testuser"

    # Now, check the current user after 25 hours
    with freeze_time(datetime.now(timezone.utc) + timedelta(hours=25)):
        response = await test_client.get("/users/current-user")
        assert response.status_code == 401
        data = response.json()
        assert data is not None
        assert "detail" in data
        assert data["detail"] == "Could not validate credentials"

    test_client.cookies.clear()  # Clear cookies to simulate token expiration
    # Clean up the test user
    await LocalUser.find_one(LocalUser.username == "testuser").delete()


@pytest.mark.asyncio
async def test_login_refresh_token(test_client: AsyncClient):
    response = await test_client.post("/users/", data=get_test_data())
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User registered successfully"
    assert data["data"]["username"] == "testuser"

    # Now, log in the user
    response = await test_client.post(
        "/users/login", data={"username": "testuser", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    assert "data" in data
    assert data["message"] == "User logged in successfully"
    assert data["data"]["user"]["username"] == "testuser"

    # Check if the access_token, refresh_token cookie is set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

    # Store the cookies in the client for future requests
    test_client.cookies.set("access_token", response.cookies.get("access_token"))
    test_client.cookies.set("refresh_token", response.cookies.get("refresh_token"))

    # Now, check the current user after 25 hours
    with freeze_time(datetime.now(timezone.utc) + timedelta(hours=25)):
        response = await test_client.get("/users/current-user")
        assert response.status_code == 401
        data = response.json()
        assert data is not None
        assert "detail" in data
        assert data["detail"] == "Could not validate credentials"

        # Now, refresh the access token
        response = await test_client.post("/users/refresh-token")
        assert response.status_code == 200
        data = response.json()
        assert data is not None
        assert "data" in data
        assert data["message"] == "Token refreshed successfully"
        assert "access_token" in data["data"]
        assert "refresh_token" in data["data"]

        # Now, set the new tokens in the client
        test_client.cookies.set("access_token", response.cookies.get("access_token"))
        test_client.cookies.set("refresh_token", response.cookies.get("refresh_token"))
        # Now, check the current user again
        response = await test_client.get("/users/current-user")
        assert response.status_code == 200
        data = response.json()
        assert data is not None
        assert data["message"] == "User fetched successfully"
        assert "data" in data
        assert data["data"]["username"] == "testuser"
    # Clean up the client cookies
    test_client.cookies.clear()
    # Clean up the test user
    await LocalUser.find_one(LocalUser.username == "testuser").delete()
