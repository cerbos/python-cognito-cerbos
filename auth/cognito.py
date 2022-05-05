import boto3


class Cognito:
    def __init__(
        self, region: str, pool_id: str, client_id: str, auth_flow: str
    ) -> None:
        self.client = boto3.client("cognito-idp")

        self._region = region
        self._pool_id = pool_id
        self._client_id = client_id
        self._auth_flow = auth_flow

    def authenticate(self, username: str, password: str) -> dict[str, str]:
        # auth_params = {
        #     "USERNAME": self.email,
        #     "SRP_A": "foo",
        # }
        # self.client.initiate_auth(
        #     AuthFlow="USER_SRP_AUTH",
        #     AuthParameters=auth_params,
        #     ClientId=self._client_id,
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

        # TODO handle challenges
        # if challenge_name := res.get("ChallengeName") is not None:
        #     pass

        try:
            return res["AuthenticationResult"]
        except KeyError:
            raise
