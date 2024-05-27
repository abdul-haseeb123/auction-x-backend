from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import users
from starlette.middleware.sessions import SessionMiddleware


app = FastAPI()
origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key="my-very-long-secret")
app.include_router(users.router)

@app.get("/")
def read_root():
    return {"Hello": "World"}

# import logging
# import sys
# log = logging.getLogger('authlib')
# log.addHandler(logging.StreamHandler(sys.stdout))
# log.setLevel(logging.DEBUG)