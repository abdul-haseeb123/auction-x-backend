from pydantic import BaseModel, field_validator
from enum import Enum
from .images import Image
from typing import Union
from datetime import datetime

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


class ListingBase(BaseModel):
    owner: str
    title: str
    description: str
    active: bool = True
    cover_image: Union[str, Image]
    listing_images: list[Union[str, Image]] = []
    category: Category
    bids: list[str] = []
    starting_bid: float
    current_bid: float
    current_winner: str
    created_at: datetime
    updated_at: datetime

class ListingCreate(BaseModel):
    title: str
    description: str
    starting_bid: float
    category: str
    closing_date: datetime
    cover_image: Union[Image, str] = None
    images: list[Union[Image, str]] = []
    bids: list[str] = []
    winner: str = None

    @field_validator("title")
    def validate_title(cls, v:str):
        if len(v) == 0:
            raise ValueError("title must not be empty")
        if len(v) > 100:
            raise ValueError("title must not exceed 100 characters")
        return v
    
    @field_validator("description")
    def validate_description(cls, v:str):
        if len(v) == 0:
            raise ValueError("description must not be empty")
        if len(v) > 1000:
            raise ValueError("description must not exceed 1000 characters")
        return v
    
    @field_validator("starting_bid")
    def validate_starting_bid(cls, v:float):
        if v < 0:
            raise ValueError("starting bid must be greater than 0")
        return v