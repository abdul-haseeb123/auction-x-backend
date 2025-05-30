from datetime import datetime
from pydantic import BaseModel, EmailStr, field_validator, Field, BeforeValidator
from typing import Annotated, Optional, Union

from ..schemas.images import Image
from ..db import users
from pymongo.asynchronous.database import AsyncDatabase




class User(BaseModel):
    id : Optional[Annotated[str, BeforeValidator(str)]] = Field(alias="_id", default=None)
    full_name: str = Field(examples=["John Doe"])
    username: str = Field(examples=["john_doe"])
    email: EmailStr
    email_verified: Optional[bool] = False
    avatar: Optional[Union[Image, str]] = None
    cover_image: Optional[Union[Image, str]] = None
    account_type: Optional[str] = Field(default="EMAIL")
    

class GoogleToken(BaseModel):
    access_token: str
    refresh_token: str
    expires_at: datetime

class GoogleUser(BaseModel):
    full_name : str
    username: str
    email: EmailStr
    email_verified: bool
    avatar: Optional[Union[Image, str]] = None
    cover_image: Optional[Union[Image, str]] = None
    account_type: Optional[str] = Field(default="GOOGLE")
    token: GoogleToken

class UserCreate(BaseModel):
    full_name: str = Field(examples=["John Doe"])
    username: str = Field(examples=["john_doe"])
    email: EmailStr
    email_verified: Optional[bool] = False
    password: str
    avatar: Optional[Union[Image, str]] = None
    cover_image: Optional[Union[Image, str]] = None
    account_type: Optional[str] = Field(default="EMAIL")

    @field_validator("username")    
    def validate_username(cls, v:str):
        if " " in v:
            raise ValueError("username must not contain space")
        return v
    @field_validator("full_name")
    def validate_full_name(cls, v:str):
        if len(v) == 0:
            raise ValueError("full name must not be empty")
        return v.title()

    @field_validator("password")
    def validate_password(cls,v:str):
        if v is None:
            raise ValueError("password cannot be empty")
        if len(v) == None:
            raise ValueError("password cannot be empty")
        return v
        

    async def save(self, db:AsyncDatabase):
        user = {
            "full_name": self.full_name,
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "avatar": self.avatar.model_dump() if self.avatar else None,
            "cover_image": self.cover_image.model_dump() if self.cover_image else None,
            "email_verified": self.email_verified,
            "account_type": self.account_type
        }
        user_id = await users.create_user(user, db)
        user["_id"] = user_id
        # print()
        return User(**user)


