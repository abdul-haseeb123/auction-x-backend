import jwt
import os
from jwt.exceptions import InvalidTokenError
from fastapi import Request, HTTPException
from ..schemas import User
from ..db import users
from datetime import datetime

async def get_current_user(request: Request) -> User:
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not request.headers.get("Authorization") and not request.cookies.get("access_token"):
        raise credentials_exception


    if request.headers.get("Authorization") != None:
        token = request.headers.get("Authorization").split(" ")[1]
    if request.cookies.get("access_token") != None:
        token = request.cookies.get("access_token")
    google_user = await users.get_google_user_by_access_token(token)
    if google_user:
        print("google user found")
        if google_user["token"]["expires_at"] < datetime.now():
            raise credentials_exception
        return User(**google_user)
    
    try:
        payload = jwt.decode(token, os.environ.get("ACCESS_TOKEN_SECRET"), algorithms=["HS256"])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = await users.get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return User(**user)

