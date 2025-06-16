from datetime import datetime
from typing import Union

import jwt
from fastapi import HTTPException, Request
from jwt.exceptions import InvalidTokenError

from ..config import settings
from ..schemas.users import GoogleUser, LocalUser


async def get_current_user(request: Request) -> Union[LocalUser, GoogleUser]:
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not request.headers.get("Authorization") and not request.cookies.get(
        "access_token"
    ):
        raise credentials_exception

    if request.headers.get("Authorization") is not None:
        token = request.headers.get("Authorization").split(" ")[1]
    if request.cookies.get("access_token") is not None:
        token = request.cookies.get("access_token")
    google_user = await GoogleUser.find_one(GoogleUser.token.access_token == token)
    if google_user:
        print("google user found")
        if google_user["token"]["expires_at"] < datetime.now():
            raise credentials_exception
        return google_user

    try:
        payload = jwt.decode(token, settings.access_token_secret, algorithms=["HS256"])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = await LocalUser.find_one(LocalUser.username == username)
    if user is None:
        raise credentials_exception
    return user
