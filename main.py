import os

# import cerbos
import requests
import uvicorn
from fastapi import Depends, FastAPI
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth.cognito import Cognito
from auth.jwt import JWTBearer, JWKS


AWS_REGION = os.environ["AWS_DEFAULT_REGION"]
AWS_COGNITO_POOL_ID = os.environ["AWS_COGNITO_POOL_ID"]
AWS_COGNITO_CLIENT_ID = os.environ["AWS_COGNITO_CLIENT_ID"]
# os.environ["AWS_ACCESS_KEY_ID"]
# os.environ["AWS_SECRET_ACCESS_KEY"]

AWS_COGNITO_AUTH_FLOW = "ADMIN_USER_PASSWORD_AUTH"


COGNITO = Cognito(
    AWS_REGION, AWS_COGNITO_POOL_ID, AWS_COGNITO_CLIENT_ID, AWS_COGNITO_AUTH_FLOW
)


JWKS_CACHED = JWKS(
    **requests.get(
        f"https://cognito-idp.{AWS_REGION}.amazonaws.com/"
        f"{AWS_COGNITO_POOL_ID}/.well-known/jwks.json"
    ).json()
)


app = FastAPI()

security = HTTPBasic()
token_auth_scheme = JWTBearer(JWKS_CACHED)


@app.get("/")
async def root():
    return {"message": "oh hello there"}


# basic auth endpoint, returning tokens:
# - `*/login` in a browser prompts login
# - `curl http://{host}:{port}/login -H "Authorization: Basic {b64encode(username + ":" + password)}"`
@app.get("/login")
async def login(credentials: HTTPBasicCredentials = Depends(security)):
    return COGNITO.authenticate(credentials.username, credentials.password)


# protected endpoint, returns username from verified jwt claims:
# `curl http://{host}:{port}/protected -H "Authorization: Bearer {id_token}"`
@app.get("/protected")
async def users(credentials: str = Depends(token_auth_scheme)):
    return credentials.claims["email"]


@app.get("/users")
async def users(credentials: str = Depends(token_auth_scheme)):
    # TODO something cerbosy
    return credentials.claims["email"]


if __name__ == "__main__":
    # uvicorn.run("main:app", host="0.0.0.0", log_level="info")
    uvicorn.run("main:app", reload=True)
