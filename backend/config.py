from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    mongodb_uri: str
    db_name: str
    test_db_name: str

    access_token_secret: str
    access_token_expiry: int
    refresh_token_secret: str
    refresh_token_expiry: int

    google_client_id: str
    google_client_secret: str

    cloudinary_name: str
    cloudinary_api_key: str
    cloudinary_api_secret: str

    oauth2_refresh_token_generator: bool

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
