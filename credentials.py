import os
from dataclasses import dataclass

import requests
from dataclasses_json import dataclass_json
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import (  # OAuth2PasswordBearer,
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from jose import JWTError, jwk, jwt
from jose.utils import base64url_decode
from starlette.status import HTTP_403_FORBIDDEN

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
bearer_scheme = HTTPBearer()


JWK = dict[str, str]


@dataclass
class JWKS:
    keys: list[JWK]


_jwks = JWKS(
    **requests.get(
        f"https://cognito-idp.{os.environ['AWS_DEFAULT_REGION']}.amazonaws.com/"
        f"{os.environ['AWS_COGNITO_POOL_ID']}/.well-known/jwks.json"
    ).json()
)
JWK_CACHE: dict[str, JWK] = {jwk["kid"]: jwk for jwk in _jwks.keys}


@dataclass_json
@dataclass
class Credentials:
    jwt_token: str
    header: dict[str, str]
    claims: dict[str, str | list[str]]  # list[str] for cognito:groups
    signature: str
    message: str


def verify_jwt(credentials: Credentials) -> bool:
    try:
        public_key = JWK_CACHE[credentials.header["kid"]]
    except KeyError:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="JWK public key not found"
        )

    key = jwk.construct(public_key)
    decoded_signature = base64url_decode(credentials.signature.encode())

    return key.verify(credentials.message.encode(), decoded_signature)


async def get_token_from_bearer(
    http_credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> str:
    if http_credentials:
        if not http_credentials.scheme == "Bearer":
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Wrong authentication method"
            )

        return http_credentials.credentials


def get_user_from_session(request: Request) -> Credentials:
    if (c := request.session.get("user_credentials")) is None:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": request.url_for("index")},
        )
    else:
        creds = Credentials.from_dict(c)

    if not verify_jwt(creds):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="JWK invalid")

    return creds


async def get_credentials_from_token(
    token: str = Depends(get_token_from_bearer),
) -> Credentials:
    message, signature = token.rsplit(".", 1)
    try:
        credentials = Credentials(
            jwt_token=token,
            header=jwt.get_unverified_header(token),
            claims=jwt.get_unverified_claims(token),
            signature=signature,
            message=message,
        )
    except JWTError:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="JWK invalid")

    if not verify_jwt(credentials):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="JWK invalid")
    return credentials
