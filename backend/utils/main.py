# from passlib.context import CryptContext
import os
import bcrypt
import cloudinary
import cloudinary.uploader
from ..schemas.images import Image

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET")
)

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password:str, hashed_password:str):
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    # return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password:str):
    # return pwd_context.hash(password)
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

async def upload_image(file) -> Image:
    uploaded = cloudinary.uploader.upload(file, resource_type="image", folder="auction_x")
    fields = ["asset_id", "public_id", "width", "height", "resource_type", "tags", "url", "secure_url"]
    for field in fields:
        if field not in uploaded:
            del uploaded[field]
    return Image(**uploaded)

async def delete_image(public_id):
    return cloudinary.uploader.destroy(public_id, resource_type="image")
    