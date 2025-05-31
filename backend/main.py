from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import users, listings
from starlette.middleware.sessions import SessionMiddleware
from contextlib import asynccontextmanager
from .utils.db import get_database
from .db.listings import ensure_slug_index
from .db.users import ensure_username_email_index

@asynccontextmanager
async def lifespan(app:FastAPI):
    db = get_database()
    await ensure_slug_index(db)
    await ensure_username_email_index(db)
    yield
    await db.client.close()


origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
]

def build_app(lifespan) -> FastAPI:
    app = FastAPI(
    title= "AuctionX API",
    root_path="/api/v1", 
    servers=[{"url": "http://localhost:8000/api/v1", "description": "Localhost server"}], lifespan=lifespan
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
    app.include_router(listings.router)

    return app


app = build_app(lifespan)


@app.get("/")
def read_root():
    return {"Hello": "World"}

# import logging
# import sys
# log = logging.getLogger('authlib')
# log.addHandler(logging.StreamHandler(sys.stdout))
# log.setLevel(logging.DEBUG)