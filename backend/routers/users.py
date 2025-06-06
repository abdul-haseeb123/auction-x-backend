from datetime import datetime, timedelta, timezone

import jwt
from fastapi import (
    APIRouter,
    HTTPException,
    Depends,
    Response,
    Request,
    UploadFile,
    File,
    Body,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from pymongo.errors import DuplicateKeyError
from pymongo.asynchronous.database import AsyncDatabase
from ..schemas.users import UserCreate, User, GoogleUser, GoogleToken
from ..schemas.apiresponse import (
    ApiResponseUser,
    ApiResponseUsers,
    ApiResponseToken,
    Token,
    RefreshToken,
    ApiResponse,
    ApiResponseRefresh,
    TokenData,
)

from ..utils.main import upload_image, delete_image, verify_password
from ..dependencies.users import get_current_user
from ..dependencies.db import get_db
import os
from authlib.integrations.starlette_client import OAuth, OAuthError
from starlette.config import Config
from ..db import users
from pydantic import ValidationError
from cloudinary.exceptions import BadRequest

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login")
config = Config(".env")
oauth = OAuth(config)
CONF_URL = "https://accounts.google.com/.well-known/openid-configuration"
oauth.register(
    name="google",
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    refresh_token_url="https://oauth2.googleapis.com/token",
    refresh_token_params=None,
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    authorize_params={"access_type": "offline"},
    api_base_url="https://www.googleapis.com/oauth2/v1/",
    client_kwargs={"scope": "openid email profile", "prompt": "consent"},
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    include_granted_scopes=True,
)


router = APIRouter(prefix="/users", tags=["users"])


async def authenticate_user(username, password, db: AsyncDatabase):
    user = await users.get_user_by_username(username, db)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user


async def generate_access_refresh_token(user: TokenData, db: AsyncDatabase):
    to_encode_access = user.model_copy().model_dump()
    to_encode_refresh = {"id": user.id}

    expire_access = datetime.now(timezone.utc) + timedelta(
        days=int(os.environ.get("ACCESS_TOKEN_EXPIRY"))
    )
    expire_refresh = datetime.now(timezone.utc) + timedelta(
        days=int(os.environ.get("REFRESH_TOKEN_EXPIRY"))
    )

    to_encode_access.update({"exp": expire_access})
    to_encode_refresh.update({"exp": expire_refresh})

    access_token = jwt.encode(
        to_encode_access, os.environ.get("ACCESS_TOKEN_SECRET"), algorithm="HS256"
    )
    refresh_token = jwt.encode(
        to_encode_refresh, os.environ.get("REFRESH_TOKEN_SECRET")
    )

    logged_in_user = await users.update_refresh_token(user.username, refresh_token, db)

    return logged_in_user, access_token, refresh_token


@router.post("/custom-refresh-google-token")
async def read_root(
    request: Request, response: Response, db: Annotated[AsyncDatabase, Depends(get_db)]
):
    access_token = request.cookies.get("refresh_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await users.get_google_user_by_refresh_token(access_token, db)
    print("user", user)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid access token")
    user_refresh_token = user["token"]["refresh_token"]
    token = await oauth.google.fetch_access_token(
        grant_type="refresh_token", refresh_token=user_refresh_token
    )
    return token


@router.get("/", response_model=ApiResponseUsers)
async def get_users(db: Annotated[AsyncDatabase, Depends(get_db)]):
    users_list = await users.get_users(db)
    return ApiResponseUsers(
        status_code=200, data=users_list, message="Users retrieved successfully"
    )


@router.get("/current-user", response_model=ApiResponseUser)
async def get_logged_in_user(current_user: Annotated[User, Depends(get_current_user)]):
    return ApiResponseUser(
        status_code=200, message="User fetched successfully", data=current_user
    )


@router.post(
    "/",
    response_model=ApiResponseUser,
    openapi_extra={
        "requestBody": {
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["full_name", "username", "email", "password"],
                        "properties": {
                            "full_name": {"type": "string", "example": "John Doe"},
                            "username": {"type": "string", "example": "john_doe"},
                            "email": {"type": "string", "example": "john@example.com"},
                            "password": {"type": "string", "example": "password"},
                            "avatar": {"type": "string", "format": "binary"},
                            "cover_image": {"type": "string", "format": "binary"},
                        },
                    }
                },
                "required": True,
            }
        }
    },
)
async def register_user(
    request: Request, db: Annotated[AsyncDatabase, Depends(get_db)]
):
    raw_body = await request.form()
    full_name = raw_body.get("full_name")
    username = raw_body.get("username")
    email = raw_body.get("email")
    password = raw_body.get("password")
    cover_image: UploadFile | None = raw_body.get("cover_image")
    avatar: UploadFile | None = raw_body.get("avatar")

    if cover_image:
        try:
            if cover_image.headers.get("content-type").startswith("image"):
                try:
                    uploaded_cover = await upload_image(cover_image.file)
                except BadRequest:
                    raise HTTPException(400, detail="Cover image must be an image file")
            else:
                raise HTTPException(400, detail="Cover image must be an image file")
        except AttributeError or KeyError or BadRequest:
            raise HTTPException(400, detail="Cover image must be an image file")
    if avatar:
        try:
            if avatar.headers.get("content-type").startswith("image"):
                try:
                    uploaded_avatar = await upload_image(avatar.file)
                except BadRequest:
                    raise HTTPException(400, detail="Avatar must be an image file")
            else:
                raise HTTPException(400, detail="Avatar must be an image file")
        except AttributeError or KeyError or BadRequest:
            raise HTTPException(400, detail="Avatar must be an image file")
    try:
        user = UserCreate(
            full_name=full_name,
            username=username,
            email=email,
            password=password,
            avatar=uploaded_avatar if avatar else None,
            cover_image=uploaded_cover if cover_image else None,
        )
    except ValidationError as e:
        raise HTTPException(400, detail=str(e))
    try:
        user = await user.save(db)
    except DuplicateKeyError:
        raise HTTPException(400, detail="Username or email already exists")
    return ApiResponseUser(
        status_code=200, message="User registered successfully", data=user
    )


@router.post("/login")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    response: Response,
    db: Annotated[AsyncDatabase, Depends(get_db)],
) -> ApiResponseToken:
    user = await authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logged_user, access_token, refresh_token = await generate_access_refresh_token(
        TokenData(**user), db
    )
    response.set_cookie("access_token", access_token, secure=True, httponly=True)
    response.set_cookie("refresh_token", refresh_token, secure=True, httponly=True)
    token = Token(
        access_token=access_token, refresh_token=refresh_token, user=logged_user
    )
    return ApiResponseToken(
        status_code=200, data=token, message="User logged in successfully"
    )


@router.get("/google")
async def login_with_google(request: Request):
    redirect_uri = request.url_for("auth_with_google")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback", response_model=ApiResponseToken)
async def auth_with_google(
    request: Request, response: Response, db: Annotated[AsyncDatabase, Depends(get_db)]
):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as error:
        raise HTTPException(400, detail=str(error))
    google_token = GoogleToken(
        access_token=token.get("access_token"),
        refresh_token=token.get("refresh_token"),
        expires_at=datetime.fromtimestamp(token.get("expires_at")),
    )

    user_info = token.get("userinfo")
    user = await users.get_user_by_email(user_info.get("email"), db)
    if not user:
        google_user = GoogleUser(
            full_name=user_info.get("name"),
            username=user_info.get("email").split("@")[0],
            email=user_info.get("email"),
            email_verified=user_info.get("email_verified"),
            avatar=user_info.get("picture"),
            account_type="GOOGLE",
            token=google_token,
        ).model_dump()

        user_id = await users.create_user(google_user, db)

        google_user["_id"] = user_id
        token_res = Token(
            access_token=token.get("access_token"),
            refresh_token=token.get("refresh_token"),
            user=User(**google_user),
        )
        response.set_cookie(
            "access_token", token.get("access_token"), secure=True, httponly=True
        )
        response.set_cookie(
            "refresh_token", token.get("refresh_token"), secure=True, httponly=True
        )
        return ApiResponseToken(
            status_code=200, data=token_res, message="User logged in successfully"
        )

    await users.update_google_token(user["username"], google_token.model_dump(), db)
    token = Token(
        access_token=token.get("access_token"),
        refresh_token=token.get("refresh_token"),
        user=User(**user),
    )
    response.set_cookie("access_token", token.access_token, secure=True, httponly=True)
    response.set_cookie(
        "refresh_token", token.refresh_token, secure=True, httponly=True
    )
    return ApiResponseToken(
        status_code=200, data=token, message="User logged in successfully"
    )


@router.post("/logout", response_model=ApiResponse)
async def logout(
    current_user: Annotated[User, Depends(get_current_user)],
    response: Response,
    request: Request,
    db: Annotated[AsyncDatabase, Depends(get_db)],
):
    if current_user.account_type == "GOOGLE":
        await users.update_google_token(current_user.username, None, db=db)
    await users.update_refresh_token(current_user.username, None, db=db)
    response.delete_cookie("access_token", secure=True, httponly=True)
    response.delete_cookie("refresh_token", secure=True, httponly=True)
    return ApiResponse(message="User logged out successfully", status_code=200)


@router.post("/refresh-token", response_model=ApiResponseRefresh)
async def refresh_token(
    request: Request, response: Response, db: Annotated[AsyncDatabase, Depends(get_db)]
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(401, "Refresh token not found")
    user = await users.get_google_user_by_refresh_token(
        refresh_token=refresh_token, db=db
    )
    if user:
        user_refresh_token = user["token"]["refresh_token"]
        token = await oauth.google.fetch_access_token(
            grant_type="refresh_token", refresh_token=user_refresh_token
        )
        print("here, ", token)
        print("token.get", token.get("access_token"))
        print("typeof token", type(token))
        new_token = GoogleToken(
            access_token=token.get("access_token"),
            refresh_token=user_refresh_token,
            expires_at=datetime.fromtimestamp(token.get("expires_at")),
        )

        await users.update_google_token(user["username"], new_token.model_dump(), db=db)
        response.set_cookie(
            "access_token", token.get("access_token"), secure=True, httponly=True
        )
        return ApiResponseRefresh(
            status_code=200,
            data=RefreshToken(
                access_token=token.get("access_token"), refresh_token=refresh_token
            ),
            message="Token refreshed successfully",
        )
    try:
        decoded = jwt.decode(
            refresh_token, os.environ.get("REFRESH_TOKEN_SECRET"), algorithms=["HS256"]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    # user = users.find_one({"_id":ObjectId(decoded["_id"])})
    user = await users.get_user_by_id(decoded["id"], db)
    if not user:
        raise HTTPException(401, "User not found")
    _, access_token, refresh_token = await generate_access_refresh_token(
        TokenData(**user), db
    )
    response.set_cookie("access_token", access_token, secure=True, httponly=True)
    response.set_cookie("refresh_token", refresh_token, secure=True, httponly=True)
    token = RefreshToken(access_token=access_token, refresh_token=refresh_token)
    return ApiResponseRefresh(
        status_code=200, data=token, message="Token refreshed successfully"
    )


@router.put(
    "/update-password",
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "status_code": {"type": "integer", "example": 200},
                            "message": {
                                "type": "string",
                                "example": "Password updated successfully",
                            },
                            "data": {"type": "null"},
                            "success": {"type": "boolean", "example": True},
                        },
                    }
                }
            },
        },
    },
)
async def update_password(
    current_user: Annotated[User, Depends(get_current_user)],
    current_password: Annotated[str, Body()],
    new_password: Annotated[str, Body()],
    db: Annotated[AsyncDatabase, Depends(get_db)],
):
    if current_user.account_type == "GOOGLE":
        raise HTTPException(400, "Cannot update password for Google account")
    is_correct_user = authenticate_user(current_user.username, current_password, db)
    if not is_correct_user:
        raise HTTPException(400, "Incorrect password")
    await users.update_password(current_user.username, new_password, db)
    return {
        "status_code": 200,
        "message": "Password updated successfully",
        "data": None,
        "success": True,
    }


@router.put("/update-profile", response_model=ApiResponseUser)
async def update_profile(
    current_user: Annotated[User, Depends(get_current_user)],
    full_name: Annotated[
        str,
        Body(examples={"default": {"value": "John Doe"}}, min_length=3, max_length=80),
    ],
    db: Annotated[AsyncDatabase, Depends(get_db)],
):
    updated_user = await users.update_full_name(
        current_user.username, full_name, db, new=True
    )
    return ApiResponseUser(
        status_code=200,
        message="Profile updated successfully",
        data=User(**updated_user),
    )


@router.put("/update-avatar", response_model=ApiResponseUser)
async def update_avatar(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncDatabase, Depends(get_db)],
    avatar: UploadFile = File(),
):
    try:
        if avatar.headers.get("content-type").startswith("image"):
            try:
                uploaded_avatar = await upload_image(avatar.file)
            except BadRequest:
                raise HTTPException(400, detail="Avatar must be an image file")
        else:
            raise HTTPException(400, detail="Avatar must be an image file")
    except AttributeError or KeyError:
        raise HTTPException(400, detail="Avatar must be an image file")
    if current_user.avatar and not isinstance(current_user.avatar, str):
        try:
            await delete_image(current_user.avatar.public_id)
        except Exception as e:
            raise HTTPException(400, detail=str(e))
    updated_user = await users.update_avatar(
        current_user.username, uploaded_avatar.model_dump(), db, new=True
    )
    return ApiResponseUser(
        status_code=200,
        message="Avatar updated successfully",
        data=User(**updated_user),
    )


@router.put("/update-cover-image", response_model=ApiResponseUser)
async def update_cover_image(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncDatabase, Depends(get_db)],
    cover_image: UploadFile = File(),
):
    try:
        if cover_image.headers.get("content-type").startswith("image"):
            try:
                uploaded_avatar = await upload_image(cover_image.file)
            except BadRequest:
                raise HTTPException(400, detail="Cover image must be an image file")
        else:
            raise HTTPException(400, detail="Cover image must be an image file")
    except AttributeError or KeyError:
        raise HTTPException(400, detail="Cover image must be an image file")
    if current_user.cover_image and not isinstance(current_user.cover_image, str):
        try:
            await delete_image(current_user.cover_image.public_id)
        except Exception as e:
            raise HTTPException(400, detail=str(e))
    updated_user = await users.update_cover_image(
        current_user.username, uploaded_avatar.model_dump(), db, new=True
    )
    return ApiResponseUser(
        status_code=200,
        message="Cover image updated successfully",
        data=User(**updated_user),
    )


@router.delete("/delete-account", response_model=ApiResponse)
async def delete_account(
    current_user: Annotated[User, Depends(get_current_user)],
    response: Response,
    db: Annotated[AsyncDatabase, Depends(get_db)],
):
    if current_user.avatar and not isinstance(current_user.avatar, str):
        try:
            await delete_image(current_user.avatar.public_id)
        except Exception as e:
            raise HTTPException(400, detail=str(e))
    if current_user.cover_image and not isinstance(current_user.cover_image, str):
        try:
            await delete_image(current_user.cover_image.public_id)
        except Exception as e:
            raise HTTPException(400, detail=str(e))
    await users.delete_user(current_user.username, db)
    response.delete_cookie("access_token", secure=True, httponly=True)
    response.delete_cookie("refresh_token", secure=True, httponly=True)
    return ApiResponse(status_code=200, message="Account deleted successfully")
