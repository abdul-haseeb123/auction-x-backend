from contextlib import asynccontextmanager

from beanie import init_beanie
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .routers import users
from .schemas.users import GoogleUser, LocalUser, User


@asynccontextmanager
async def lifespan(app: FastAPI):
    cli = AsyncIOMotorClient(settings.mongodb_uri)
    await init_beanie(
        database=cli[settings.db_name], document_models=[User, LocalUser, GoogleUser]
    )
    yield
    cli.close()


origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
]


def build_app(lifespan) -> FastAPI:
    app = FastAPI(
        title="AuctionX API",
        root_path="/api/v1",
        servers=[
            {"url": "http://localhost:8000/api/v1", "description": "Localhost server"}
        ],
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(SessionMiddleware, secret_key="my-very-long-secret")
    app.include_router(users.router)
    # app.include_router(listings.router)

    return app


app = build_app(lifespan)


@app.get("/")
def read_root():
    return {"Hello": "World"}
