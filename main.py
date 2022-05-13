import json
import os
from urllib import parse as url_parse

import requests
import uvicorn
from cerbos.sdk.client import CerbosClient
from cerbos.sdk.model import Principal, Resource, ResourceAction, ResourceList
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from pycognito import Cognito
from pycognito.exceptions import ForceChangePasswordException
from starlette.middleware.sessions import SessionMiddleware

from jwt import Credentials, get_credentials_from_token

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
AWS_DEFAULT_REGION = os.environ["AWS_DEFAULT_REGION"]

AWS_COGNITO_CLIENT_ID = os.environ["AWS_COGNITO_CLIENT_ID"]
AWS_COGNITO_CLIENT_SECRET = os.getenv("AWS_COGNITO_CLIENT_SECRET")
AWS_COGNITO_POOL_ID = os.environ["AWS_COGNITO_POOL_ID"]
AWS_COGNITO_POOL_NAME = os.getenv("AWS_COGNITO_POOL_NAME")

# Optional envvars to be set if you want to enable hosted Cognito UI login
AWS_COGNITO_HOSTED_UI_CALLBACK_URL = os.getenv("AWS_COGNITO_HOSTED_UI_CALLBACK_URL")
AWS_COGNITO_HOSTED_UI_LOGOUT_URL = os.getenv("AWS_COGNITO_HOSTED_UI_LOGOUT_URL")


app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="super-secret-key!")

templates = Jinja2Templates(directory="templates")


def get_hosted_url(
    path: str, extra_qs_params: dict = None, override_qs_params: bool = False
) -> str | None:
    if not AWS_COGNITO_HOSTED_UI_CALLBACK_URL or not AWS_COGNITO_HOSTED_UI_LOGOUT_URL:
        return None

    qs_params = {
        "client_id": AWS_COGNITO_CLIENT_ID,
        "response_type": "code",
        "scope": "email+openid",
        "redirect_uri": AWS_COGNITO_HOSTED_UI_CALLBACK_URL,
    }
    if extra_qs_params:
        qs_params = (
            extra_qs_params if override_qs_params else qs_params | extra_qs_params
        )

    url = url_parse.urlunsplit(
        [
            "https",
            f"{AWS_COGNITO_POOL_NAME}.auth.{AWS_DEFAULT_REGION}.amazoncognito.com",
            path,
            url_parse.urlencode(
                qs_params,
                safe="+",  # scope expects `+` delimiters
                quote_via=url_parse.quote,
            ),
            "",
        ]
    )

    return url


def prettify_json(data: dict) -> str:
    return json.dumps(data, sort_keys=False, indent=2)


def get_user_from_session(request: Request) -> dict:
    creds = request.session.get("user_credentials")
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": request.url_for("index")},
        )
    return Credentials.from_dict(creds)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    template_ctx = {"request": request}
    if (url := get_hosted_url("/oauth2/authorize")) is not None:
        template_ctx["hosted_url"] = url
    return templates.TemplateResponse("index.html", template_ctx)


# Local login endpoint
@app.post("/login")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    c = Cognito(AWS_COGNITO_POOL_ID, AWS_COGNITO_CLIENT_ID, username=form_data.username)
    try:
        c.authenticate(password=form_data.password)
        # optionally, use admin_authenticate method for super privileges (bypassing auth challenges)
        # c.admin_authenticate(password=data.password)
    except ForceChangePasswordException:
        # TODO not implemented password change UI
        return templates.TemplateResponse(
            "index.html", {"request": request, "errors": ["Password change required"]}
        )
    except c.client.exceptions.NotAuthorizedException:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "errors": ["Incorrect username or password"]},
        )
    except Exception:
        return templates.TemplateResponse(
            "index.html", {"request": request, "errors": ["Something went wrong"]}
        )

    credentials = await get_credentials_from_token(c.access_token)
    request.session["user_credentials"] = credentials.to_dict()
    return RedirectResponse(url="/user", status_code=status.HTTP_303_SEE_OTHER)


# Used by the hosted UI, if enabled
@app.get("/callback")
async def callback(request: Request):
    code = request.query_params["code"]
    # retrieve tokens from `/oauth2/tokens`
    try:
        url = get_hosted_url(
            "oauth2/token",
            {
                "grant_type": "authorization_code",
                "client_id": AWS_COGNITO_CLIENT_ID,
                "redirect_uri": AWS_COGNITO_HOSTED_UI_CALLBACK_URL,
                "code": code,
            },
            override_qs_params=True,
        )
        r = requests.post(
            url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        tokens = r.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )

    credentials = await get_credentials_from_token(tokens["access_token"])
    request.session["user_credentials"] = credentials.to_dict()
    request.session["used_hosted"] = True
    return RedirectResponse(url="/user")


@app.get("/logout")
async def logout(request: Request):
    request.session.pop("user_credentials")
    # If hosted login was used to sign in, redirect to the hosted logout
    # it will ultimately redirect back to `logout_uri`
    if request.session.pop("used_hosted", None):
        url = get_hosted_url("logout", {"logout_uri": AWS_COGNITO_HOSTED_UI_LOGOUT_URL})
        return RedirectResponse(url=url)
    return RedirectResponse(url="/")


@app.get("/user", response_class=HTMLResponse)
async def user(request: Request, credentials: dict = Depends(get_user_from_session)):
    claims = credentials.claims
    user_id: str = claims["sub"]
    roles: list[str] = claims.get("cognito:groups", [])
    # override roles for demonstrative purposes
    # roles = ["user"]

    principal = Principal(
        user_id,
        roles=roles,
        policy_version="20210210",
        attr={
            "foo": "bar",
        },
    )

    # resources would usually be retrieved from your data store
    actions = ["read", "update", "delete"]
    resource_list = ResourceList(
        resources=[
            # This resource is owned by the user making the request
            ResourceAction(
                Resource(
                    "abc123",
                    "contact",
                    attr={
                        "owner": user_id,
                    },
                ),
                actions=actions,
            ),
            # This resource is owned by someone else
            ResourceAction(
                Resource(
                    "def456",
                    "contact",
                    attr={
                        "owner": "other_user_id",
                    },
                ),
                actions=actions,
            ),
        ]
    )

    with CerbosClient(host="http://localhost:3592") as c:
        # # usually check for a specific action
        # action = "read"
        # if not c.is_allowed(action, principal, r):
        #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
        # return {
        #     "id": user_id,
        #     "foo": "bar",
        # }
        try:
            resp = c.check_resources(principal=principal, resources=resource_list)
            resp.raise_if_failed()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized"
            )

    return templates.TemplateResponse(
        "user.html",
        {
            "user_id": user_id,
            "request": request,
            "jwt": prettify_json(claims),
            "cerbosPayload": prettify_json(
                {
                    "principal": principal.to_dict(),
                    "resource_list": resource_list.to_dict(),
                }
            ),
            "cerbosResponse": resp,
            "cerbosResponseJson": prettify_json(resp.to_dict()),
        },
    )


# This endpoint requires the access token to be passed in the Authorization header,
# as an alternative to using session cookies.
# `curl http://{host}:{port}/protected -H "Authorization: Bearer {access_token}"`
@app.get("/protected")
async def protected(
    credentials: Credentials = Depends(get_credentials_from_token),
):
    return credentials


if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
