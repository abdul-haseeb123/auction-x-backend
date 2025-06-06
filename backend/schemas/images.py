from pydantic import BaseModel, Field


class Image(BaseModel):
    asset_id: str = Field(examples=["807f172fcb44ca867c1239471c0774be"])
    public_id: str = Field(examples=["auction_x/bydsawxwptlpgzh7herp"])
    width: int = Field(examples=[1920])
    height: int = Field(examples=[1080])
    resource_type: str = Field(examples=["image"])
    tags: list[str] = Field(default_factory=list)
    url: str = Field(
        examples=[
            "http://res.cloudinary.com/auction_x/image/upload/v1633661234/auction_x/bydsawxwptlpgzh7herp.jpg"
        ]
    )
    secure_url: str = Field(
        examples=[
            "https://res.cloudinary.com/auction_x/image/upload/v1633661234/auction_x/bydsawxwptlpgzh7herp.jpg"
        ]
    )
