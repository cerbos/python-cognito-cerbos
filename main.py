import os

import requests
import uvicorn
from cerbos.sdk.client import CerbosClient
from cerbos.sdk.model import Principal, Resource
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pycognito import Cognito
from pycognito.exceptions import ForceChangePasswordException
from starlette.status import HTTP_403_FORBIDDEN

from jwt import JWKS, JWTAuthorizationCredentials, JWTBearer, TokenResponse


AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION")

AWS_COGNITO_CLIENT_ID = os.environ["AWS_COGNITO_CLIENT_ID"]
AWS_COGNITO_CLIENT_SECRET = os.getenv("AWS_COGNITO_CLIENT_SECRET")
AWS_COGNITO_POOL_ID = os.environ["AWS_COGNITO_POOL_ID"]

JWKS_CACHED = JWKS(
    **requests.get(
        f"https://cognito-idp.{AWS_DEFAULT_REGION}.amazonaws.com/"
        f"{AWS_COGNITO_POOL_ID}/.well-known/jwks.json"
    ).json()
)

app = FastAPI()
basic_auth_scheme = HTTPBasic()
token_auth_scheme = JWTBearer(JWKS_CACHED)


@app.get("/")
async def root():
    return {"message": "oh hello there"}


# basic auth endpoint, returning tokens:
# - `*/login` in a browser prompts login
# - `curl http://{host}:{port}/login -H "Authorization: Basic {b64encode(username + ":" + password)}"`
@app.get("/login")
async def login(credentials: HTTPBasicCredentials = Depends(basic_auth_scheme)):
    c = Cognito(AWS_COGNITO_POOL_ID, AWS_COGNITO_CLIENT_ID, username=credentials.username)
    try:
        c.authenticate(password=credentials.password)
        # TODO optionally, use admin_authenticate method for super privileges (bypassing auth challenges)
        # c.admin_authenticate(password=credentials.password)
    except ForceChangePasswordException:
        # TODO redirect to password reset page
        pass
    except Exception as e:  # TODO
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Unauthorized")

    return TokenResponse(c.access_token, c.id_token, c.refresh_token, c.token_type)


# protected endpoint, returns username from verified jwt claims:
# `curl http://{host}:{port}/protected -H "Authorization: Bearer {id_token}"`
@app.get("/protected")
async def protected(
    credentials: JWTAuthorizationCredentials = Depends(token_auth_scheme),
):
    return credentials


@app.get("/user")
async def user(credentials: JWTAuthorizationCredentials = Depends(token_auth_scheme)):
    claims = credentials.claims

    user_id: str = claims["sub"]
    groups: list[str] = claims.get("cognito:groups", [])

    p = Principal(
        user_id,
        roles=groups,
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
        ## usually check for a specific action
        # action = "read"
        # if not c.is_allowed(action, p, r):
        #     raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Unauthorized")
        # return {
        #     "id": user_id,
        #     "email": claims["email"],
        #     "foo": "bar",
        # }

        return {
            a: c.is_allowed(a, p, r) for a in ["read", "create", "update", "delete"]
        }


if __name__ == "__main__":
    # uvicorn.run("main:app", host="0.0.0.0", log_level="info")
    uvicorn.run("main:app", reload=True)
