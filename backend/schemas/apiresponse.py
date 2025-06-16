from typing import List, Union

from pydantic import BaseModel, Field

from .listings import ListingCreate, ListingList
from .users import GoogleUser, LocalUser


class TokenData(BaseModel):
    id: str
    username: str
    email: str
    full_name: str


class Token(BaseModel):
    user: Union[LocalUser, GoogleUser]
    access_token: str
    refresh_token: str


class RefreshToken(BaseModel):
    access_token: str
    refresh_token: str


class ApiResponse(BaseModel):
    status_code: int = Field(examples=[200], default=200)
    message: str
    success: bool = True


class ApiResponseUser(ApiResponse):
    data: Union[LocalUser, GoogleUser]


class ApiResponseUsers(ApiResponse):
    data: List[Union[LocalUser, GoogleUser]]


class ApiResponseToken(ApiResponse):
    data: Token


class ApiResponseRefresh(ApiResponse):
    data: RefreshToken


class ApiResponseListing(ApiResponse):
    data: ListingCreate


class ApiResponseListings(ApiResponse):
    data: List[ListingList]
