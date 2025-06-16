import bcrypt
import cloudinary
import cloudinary.uploader

from ..config import settings
from ..schemas.images import Image

cloudinary.config(
    cloud_name=settings.cloudinary_name,
    api_key=settings.cloudinary_api_key,
    api_secret=settings.cloudinary_api_secret,
)


def verify_password(plain_password: str, hashed_password: str):
    """Verifies a plain password against a hashed password.
    Args:
        plain_password (str): The plain password to verify.
        hashed_password (str): The hashed password to compare against.
    Returns:
        bool: True if the passwords match, False otherwise.
    """
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


def get_password_hash(password: str):
    """Hashes a password using bcrypt.
    Args:
        password (str): The password to hash.
    Returns:
        str: The hashed password.
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


async def upload_image(file) -> Image:
    """Uploads an image to Cloudinary and returns an Image object.
    Args:
        file: The file to upload, typically a binary file or a file-like object.
    Returns:
        Image: An Image object containing the details of the uploaded image.
    """
    uploaded = cloudinary.uploader.upload(
        file, resource_type="image", folder="auction_x"
    )
    fields = [
        "asset_id",
        "public_id",
        "width",
        "height",
        "resource_type",
        "tags",
        "url",
        "secure_url",
    ]
    for field in fields:
        if field not in uploaded:
            del uploaded[field]
    return Image(**uploaded)


async def delete_image(public_id):
    return cloudinary.uploader.destroy(public_id, resource_type="image")
