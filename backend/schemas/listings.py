from pydantic import BaseModel, field_validator, Field, BeforeValidator
from enum import Enum
from .images import Image
from typing import Union, Optional, Annotated
from datetime import datetime
from slugify import slugify
import uuid


class Category(str, Enum):
    Fashion = "Fashion"
    Electronics = "Electronics"
    Home_Garden = "Home & Garden"
    Toy_Games = "Toy & Games"
    Collectibles = "Collectibles"
    Sports_Outdoors = "Sports & Outdoors"
    Books_Magazines = "Books & Magazines"
    Automotives = "Automotives"
    Music_Entertainment = "Music & Entertainment"
    Art_Crafts = "Art & Crafts"
    Food_Beverages = "Food & Beverages"
    Pets = "Pets"
    Other = "Other"

    class Config:
        use_enum_values = True


class Bid(BaseModel):
    user: str
    amount: float
    created_at: datetime


class ListingBase(BaseModel):
    owner: str
    title: str = Field(
        min_length=3,
        max_length=100,
        description="Title must be between 3 and 100 characters",
    )
    slug: str = Field(
        default_factory=lambda data: slugify(data.title) + "-" + str(uuid.uuid4())[:8],
        description="Unique slug for the listing",
    )
    description: str = Field(min_length=10, max_length=1000)
    active: bool = True
    closing_date: datetime
    category: Category
    bids: list[Bid] = []
    starting_bid: float = Field(gt=0, description="Starting bid must be greater than 0")
    current_bid: float = 0
    winner: str | None = None

    @field_validator("title")
    def validate_title(cls, v: str):
        if len(v) == 0:
            raise ValueError("title must not be empty")
        if len(v) > 100:
            raise ValueError("title must not exceed 100 characters")
        return v

    @field_validator("description")
    def validate_description(cls, v: str):
        if len(v) == 0:
            raise ValueError("description must not be empty")
        if len(v) > 1000:
            raise ValueError("description must not exceed 1000 characters")
        return v

    @field_validator("starting_bid")
    def validate_starting_bid(cls, v: float):
        if v < 0:
            raise ValueError("starting bid must be greater than 0")
        return v


class ListingCreate(ListingBase):
    id: Optional[Annotated[str, BeforeValidator(str)]] = Field(
        alias="_id", default=None
    )
    cover_image: Union[Image, str] = None
    images: list[Union[Image, str]] = []
    created_at: datetime
    updated_at: datetime


class ListingUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[Category] = None
    starting_bid: Optional[float] = None
    closing_date: Optional[datetime] = None


class ListingList(ListingBase):
    id: Optional[Annotated[str, BeforeValidator(str)]] = Field(
        alias="_id", default=None
    )
    cover_image: Union[Image, str] = None


class ListingDetail(ListingBase):
    id: Optional[Annotated[str, BeforeValidator(str)]] = Field(
        alias="_id", default=None
    )
    cover_image: Union[Image, str] = None
    images: list[Union[Image, str]] = []
    created_at: datetime
    updated_at: datetime
