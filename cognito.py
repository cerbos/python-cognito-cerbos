import os
from dataclasses import dataclass

import boto3
import requests
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode


# TODO typing lib for backwards compat?
JWK = dict[str, str]
JWKS = dict[str, list[JWK]]


def get_hmac_key(token: str, jwks: JWKS) -> JWK | None:
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except JWTError:
        return None
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key


def verify_jwt(token: str, jwks: JWKS) -> bool:
    hmac_key = get_hmac_key(token, jwks)
    if not hmac_key:
        raise ValueError("No pubic key found!")

    # hmac_key = jwk.construct(get_hmac_key(token, jwks))
    hmac_key = jwk.construct(hmac_key)

    message, encoded_signature = token.rsplit(".", 1)
    decoded_signature = base64url_decode(encoded_signature.encode())

    return hmac_key.verify(message.encode(), decoded_signature)


@dataclass
class TokenStore:
    IdToken: str
    RefreshToken: str
    AccessToken: str
    TokenType: str
    ExpiresIn: int

    @property
    def id_token(self) -> str:
        return self.IdToken

    @property
    def access_token(self) -> str:
        return self.AccessToken

    @property
    def refresh_token(self) -> str:
        return self.RefreshToken

    @property
    def token_type(self) -> str:
        return self.TokenType

    @property
    def expires_in(self) -> str:
        return self.ExpiresIn


class Cognito:
    def __init__(self, region: str, pool_id: str, client_id: str, auth_flow: str) -> None:
        self.client = boto3.client("cognito-idp")

        self._region = region
        self._pool_id = pool_id
        self._client_id = client_id
        self._auth_flow = auth_flow

        self._jwks: JWKS = None

    def get_jwks(self) -> JWKS:
        if self._jwks is None:
            self._jwks = requests.get(
                f"https://cognito-idp.{self._region}.amazonaws.com/"
                f"{self._pool_id}/.well-known/jwks.json"
            ).json()
        return self._jwks

    def authenticate(self, username: str, password: str) -> TokenStore:
        # auth_params = {
        #     "USERNAME": self.email,
        #     "SRP_A": "foo",
        # }
        # self.client.initiate_auth(
        #     AuthFlow="USER_SRP_AUTH",
        #     AuthParameters=auth_params,
        #     ClientId=AWS_COGNITO_CLIENT_ID,
        # )

        auth_params = {
            "USERNAME": username,
            "PASSWORD": password,
        }
        res = self.client.admin_initiate_auth(
            UserPoolId=self._pool_id,
            ClientId=self._client_id,
            AuthFlow=self._auth_flow,
            AuthParameters=auth_params,
        )
        if challenge_name := res.get("ChallengeName") is not None:
            # TODO handle challenges
            pass

        try:
            tokens = res["AuthenticationResult"]
        except KeyError:
            raise

        return TokenStore(**tokens)

    def verify_tokens(self, token_store: TokenStore) -> bool:
        return verify_jwt(token_store.id_token, self.get_jwks())
        # return verify_jwt("a", self.get_jwks())
