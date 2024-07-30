from pydantic import BaseModel, Field,BeforeValidator
from typing import Any, List, Annotated
from .users import User
from .listings import ListingCreate, ListingList

class TokenData(BaseModel):
    id : Annotated[str, BeforeValidator(str)] = Field(alias="_id")
    username: str
    email: str
    full_name: str


class Token(BaseModel):
    user: User
    access_token : str
    refresh_token: str

class RefreshToken(BaseModel):
    access_token: str
    refresh_token: str

class ApiResponse(BaseModel):
    status_code: int = Field(examples=[200], default=200)
    message: str
    success: bool = True

class ApiResponseUser(ApiResponse):
    data: User


class ApiResponseUsers(ApiResponse):
    data: List[User]

class ApiResponseToken(ApiResponse):
    data: Token

class ApiResponseRefresh(ApiResponse):
    data: RefreshToken

class ApiResponseListing(ApiResponse):
    data: ListingCreate

class ApiResponseListings(ApiResponse):
    data: List[ListingList]