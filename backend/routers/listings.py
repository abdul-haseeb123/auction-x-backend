from datetime import datetime

from fastapi import APIRouter, Depends, UploadFile, File, Body, Request, Response, HTTPException
from typing import Annotated
from ..dependencies.users import get_current_user
from ..schemas.listings import ListingCreate, Category
from ..schemas.users import User
from ..utils.main import upload_image, delete_image

router = APIRouter(prefix="/listings", tags=["listings"])


@router.get("/")
async def get_all_listings():
    return {"message": "get all listings"}

@router.post("/")
async def create_listing(current_user:Annotated[User, Depends(get_current_user)] ,title: str = Body(), description: str = Body(), category: Category = Body(), starting_bid: float = Body(), closing_date: datetime = Body(), cover_image : UploadFile = File(), images: list[UploadFile] = File()):
    if starting_bid < 0:
        raise HTTPException(400, detail="Starting bid must be greater than 0")
    try:
        if cover_image.headers.get("content-type").startswith("image"):
            uploaded_cover = await upload_image(cover_image.file)
        else:
            raise HTTPException(400, detail="Cover image must be an image file")
    except Exception as e:
        raise HTTPException(400, detail=str(e))
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
                
    return {"message": "create listing"}

@router.get("/{listing_id}")
async def get_listing(listing_id: str):
    return {"message": f"get listing {listing_id}"}

@router.put("/{listing_id}")
async def update_listing(listing_id: str):
    return {"message": f"update listing {listing_id}"}

@router.delete("/{listing_id}")
async def delete_listing(listing_id: str):
    return {"message": f"delete listing {listing_id}"}

@router.post("/{listing_id}/images")
async def upload_images(listing_id: str, images: list[UploadFile] = File(...)):
    return {"message": f"upload images to listing {listing_id}"}

@router.delete("/{listing_id}/images/{image_id}")
async def delete_image(listing_id: str, image_id: str):
    return {"message": f"delete image {image_id} from listing {listing_id}"}
