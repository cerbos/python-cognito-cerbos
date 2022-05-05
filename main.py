import os

import requests
import uvicorn
from cerbos.sdk.client import CerbosClient
from cerbos.sdk.model import Principal, Resource
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth.cognito import Cognito
from auth.jwt import JWKS, JWTBearer, JWTAuthorizationCredentials


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
basic_auth_scheme = HTTPBasic()
token_auth_scheme = JWTBearer(JWKS_CACHED)

# CERBOS = CerbosClient(host="http://localhost:3592", debug=True, tls_verify=False)
# CERBOS = CerbosClient(host="http://localhost:3592")


@app.get("/")
async def root():
    return {"message": "oh hello there"}


# basic auth endpoint, returning tokens:
# - `*/login` in a browser prompts login
# - `curl http://{host}:{port}/login -H "Authorization: Basic {b64encode(username + ":" + password)}"`
@app.get("/login")
async def login(credentials: HTTPBasicCredentials = Depends(basic_auth_scheme)):
    return COGNITO.authenticate(credentials.username, credentials.password)


# protected endpoint, returns username from verified jwt claims:
# `curl http://{host}:{port}/protected -H "Authorization: Bearer {id_token}"`
@app.get("/protected")
async def protected(credentials: JWTAuthorizationCredentials = Depends(token_auth_scheme)):
    return credentials


@app.get("/users")
async def users(credentials: JWTAuthorizationCredentials = Depends(token_auth_scheme)):
    claims = credentials.claims

    user_id: str = claims["sub"]
    groups: list[str] = claims.get("cognito:groups", [])

    p = Principal(
        user_id,
        roles=set(groups),
        # roles={"admin"},
        policy_version="20210210",
        attr={
            "email": claims["email"],
        },
    )
    r = Resource(
        "abc123",
        "contact",
        attr={
            # "owner": user_id,
            "owner": "other_user_id",
        },
    )

    with CerbosClient(host="http://localhost:3592") as c:
        return {a: c.is_allowed(a, p, r) for a in ["read", "create", "update", "delete"]}


if __name__ == "__main__":
    # uvicorn.run("main:app", host="0.0.0.0", log_level="info")
    uvicorn.run("main:app", reload=True)
