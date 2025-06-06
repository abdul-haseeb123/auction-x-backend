import pytz
import uuid
from datetime import datetime, timezone
from slugify import slugify

from fastapi import APIRouter, Depends, UploadFile, File, Body, HTTPException
from typing import Annotated
from ..dependencies.users import get_current_user
from ..schemas.listings import ListingCreate, Category, ListingUpdate, Bid
from ..schemas.apiresponse import ApiResponseListing, ApiResponseListings, ApiResponse
from ..schemas.users import User
from ..utils.main import upload_image, delete_image
from ..db import listings


router = APIRouter(prefix="/listings", tags=["listings"])


@router.get("/", response_model=ApiResponseListings)
async def get_all_listings():
    all_listings = await listings.get_listings()
    return ApiResponseListings(
        message="Listings retrieved successfully", data=all_listings
    )


@router.post("/", response_model=ApiResponseListing)
async def create_listing(
    current_user: Annotated[User, Depends(get_current_user)],
    title: str = Body(),
    description: str = Body(),
    category: Category = Body(),
    starting_bid: float = Body(),
    closing_date: datetime = Body(default="2024-05-29T15:54:36+05:00"),
    cover_image: UploadFile = File(),
    images: list[UploadFile] = File(),
):
    if closing_date < pytz.utc.localize(datetime.now()):
        raise HTTPException(400, detail="Closing date must be in the future")
    if starting_bid < 0:
        raise HTTPException(400, detail="Starting bid must be greater than 0")
    if len(title) == 0:
        raise HTTPException(400, detail="Title must not be empty")
    if len(title) > 100:
        raise HTTPException(400, detail="Title must not exceed 100 characters")
    if len(description) == 0:
        raise HTTPException(400, detail="Description must not be empty")
    if len(description) > 1000:
        raise HTTPException(400, detail="Description must not exceed 1000 characters")
    if len(images) == 0:
        raise HTTPException(400, detail="Listing must have at least one image")
    try:
        uploaded_images = []
        for image in images:
            if not image.headers.get("content-type").startswith("image"):
                raise HTTPException(400, detail="Listing images must be image files")

        for image in images:
            uploaded_image = await upload_image(image.file)
            uploaded_images.append(uploaded_image)
    except Exception as e:
        raise HTTPException(400, detail=str(e))
    try:
        if cover_image.headers.get("content-type").startswith("image"):
            uploaded_cover = await upload_image(cover_image.file)
        else:
            raise HTTPException(400, detail="Cover image must be an image file")
    except Exception as e:
        raise HTTPException(400, detail=str(e))
    date_creation = datetime.now(timezone.utc)
    slug = slugify(title) + "-" + str(uuid.uuid4())[:8]
    listing = ListingCreate(
        owner=current_user.id,
        title=title,
        description=description,
        starting_bid=starting_bid,
        category=category,
        closing_date=closing_date,
        cover_image=uploaded_cover,
        images=uploaded_images,
        created_at=date_creation,
        updated_at=date_creation,
        slug=slug,
    )
    listing_id = await listings.create_listing(listing.model_dump())
    listing.id = str(listing_id)
    return ApiResponseListing(message="Listing created successfully", data=listing)


@router.get("/{listing_slug}", response_model=ApiResponseListing)
async def get_listing(listing_slug: str):
    listing = await listings.get_listing_by_slug(listing_slug)
    if not listing:
        raise HTTPException(404, detail="Listing not found")
    if listing["closing_date"] < pytz.utc.localize(datetime.now()):
        # update the listing to inactive
        if len(listing["bids"]) > 0 and not listing["winner"] and listing["active"]:
            listing = await listings.update_listing(
                listing_slug, {"active": False, "winner": listing["bids"][-1]["user"]}
            )
        elif listing["active"]:
            listing = await listings.update_listing(listing_slug, {"active": False})
    return ApiResponseListing(message="Listing retrieved successfully", data=listing)


@router.put("/{listing_slug}", response_model=ApiResponseListing)
async def update_listing(
    current_user: Annotated[User, Depends(get_current_user)],
    listing_slug: str,
    data: ListingUpdate,
):
    """
    All values define in the schema are optional, but atleast one is required
    """
    if not any(data.model_dump().values()):
        raise HTTPException(400, detail="At least one field is required")
    if data.closing_date and data.closing_date < pytz.utc.localize(datetime.now()):
        raise HTTPException(400, detail="Closing date must be in the future")
    listing = await listings.get_listing_by_slug(listing_slug)
    if not listing:
        raise HTTPException(404, detail="Listing not found")
    if len(listing.get("bids", [])) > 0:
        raise HTTPException(400, detail="Listing has bids and cannot be updated")
    if listing["owner"] != current_user.id:
        raise HTTPException(400, detail="Listing does not belong to user")
    dict_data = data.model_dump()
    for data in list(dict_data.keys()):
        if dict_data[data] is None:
            del dict_data[data]
    updated_listing = await listings.update_listing(listing_slug, dict_data, new=True)
    return ApiResponseListing(
        message="Listing updated successfully", data=updated_listing
    )


@router.put("/{listing_slug}/cover-image", response_model=ApiResponseListing)
async def update_listing_cover_image(
    current_user: Annotated[User, Depends(get_current_user)],
    listing_slug: str,
    cover_image: UploadFile = File(...),
):
    listing = await listings.get_listing_by_slug(listing_slug)
    if not listing:
        raise HTTPException(404, detail="Listing not found")
    if listing["owner"] != current_user.id:
        raise HTTPException(400, detail="Listing does not belong to user")
    if not cover_image.headers.get("content-type").startswith("image"):
        raise HTTPException(400, detail="Cover image must be an image file")
    try:
        uploaded_cover = await upload_image(cover_image.file)
        await delete_image(listing["cover_image"]["public_id"])
    except Exception as e:
        raise HTTPException(400, detail=str(e))
    updated_listing = await listings.update_listing(
        listing_slug, {"cover_image": uploaded_cover}, new=True
    )
    return ApiResponseListing(
        message="Cover image updated successfully", data=updated_listing
    )


@router.post("/{listing_slug}/bids", response_model=ApiResponseListing)
async def place_bid(
    current_user: Annotated[User, Depends(get_current_user)],
    listing_slug: str,
    bid: float = Body(...),
):
    listing = await listings.get_listing_by_slug(listing_slug)
    if not listing:
        raise HTTPException(404, detail="Listing not found")
    if listing["closing_date"] < pytz.utc.localize(datetime.now()):
        # update the listing to inactive
        if len(listing["bids"]) > 0:
            await listings.update_listing(
                listing_slug, {"active": False, "winner": listing["bids"][-1]["user"]}
            )
        else:
            await listings.update_listing(listing_slug, {"active": False})
        raise HTTPException(400, detail="Listing has closed")
    if listing["owner"] == current_user.id:
        raise HTTPException(400, detail="Owner cannot place bid on listing")
    if bid <= listing["current_bid"]:
        raise HTTPException(400, detail="Bid must be greater than current bid")
    if bid < listing["starting_bid"]:
        raise HTTPException(400, detail="Bid must be greater than starting bid")
    if bid <= 0:
        raise HTTPException(400, detail="Bid must be greater than 0")
    if not listing["active"]:
        raise HTTPException(400, detail="Listing is not active")
    if len(listing["bids"]) > 0 and listing["bids"][-1]["user"] == current_user.id:
        raise HTTPException(400, detail="Cannot bid on own bid")
    # Add the bid to the listing
    new_bid = Bid(
        user=current_user.id, amount=bid, created_at=datetime.now(timezone.utc)
    )
    updated_listing = await listings.update_listing_bid(
        listing_slug, new_bid.model_dump(), new=True
    )
    return ApiResponseListing(message="Bid placed successfully", data=updated_listing)


@router.delete("/{listing_slug}", response_model=ApiResponse)
async def delete_listing(
    current_user: Annotated[User, Depends(get_current_user)], listing_slug: str
):
    listing = await listings.get_listing_by_slug(listing_slug)
    if not listing:
        raise HTTPException(404, detail="Listing not found")
    try:
        await listings.delete_listing(current_user.username, listing_slug)
    except ValueError:
        raise HTTPException(400, detail="Listing does not belong to user")
    try:
        for image in listing["images"]:
            await delete_image(image["public_id"])
        await delete_image(listing["cover_image"]["public_id"])
    except Exception as e:
        raise HTTPException(400, detail=str(e))
    return ApiResponse(message="Listing deleted successfully")


@router.post("/{listing_slug}/images")
async def upload_images(listing_slug: str, images: list[UploadFile] = File(...)):
    return {"message": f"upload images to listing {listing_slug}"}


@router.delete("/{listing_slug}/images/{image_id}")
async def delete_listing_image(listing_slug: str, image_id: str):
    return {"message": f"delete image {image_id} from listing {listing_slug}"}
