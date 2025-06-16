from datetime import datetime
from typing import Annotated, Optional, Union

from beanie import Document, Indexed, UnionDoc
from pydantic import BaseModel, EmailStr, Field

from ..schemas.images import Image


class GoogleToken(BaseModel):
    access_token: str
    refresh_token: str
    expires_at: datetime


class User(UnionDoc):
    class Settings:
        name = "users"


class LocalUser(Document):
    full_name: str = Field(examples=["John Doe"], min_length=3, max_length=80)
    username: Annotated[str, Indexed(unique=True)] = Field(
        examples=["john_doe"], min_length=3, max_length=120
    )
    email: Annotated[EmailStr, Indexed(unique=True)]
    email_verified: Optional[bool] = False
    password: Annotated[
        str,
        Field(min_length=6, exclude=True),
    ]
    token: Optional[str] = Field(exclude=True, default=None)
    avatar: Optional[Union[Image, str]] = None
    cover_image: Optional[Union[Image, str]] = None
    account_type: Optional[str] = Field(default="EMAIL")

    class Settings:
        union_doc = User


class GoogleUser(Document):
    full_name: str
    username: str
    email: EmailStr
    email_verified: bool
    avatar: Optional[Union[Image, str]] = None
    cover_image: Optional[Union[Image, str]] = None
    account_type: Optional[str] = Field(default="GOOGLE")
    token: GoogleToken

    class Settings:
        union_doc = User
