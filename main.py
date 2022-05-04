import os
from dataclasses import dataclass

import boto3
import cerbos
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from cognito import Cognito

AWS_COGNITO_AUTH_FLOW = "ADMIN_USER_PASSWORD_AUTH"

AWS_REGION = os.environ["AWS_DEFAULT_REGION"]
AWS_COGNITO_POOL_ID = os.environ["AWS_COGNITO_POOL_ID"]
AWS_COGNITO_CLIENT_ID = os.environ["AWS_COGNITO_CLIENT_ID"]
# os.environ["AWS_ACCESS_KEY_ID"]
# os.environ["AWS_SECRET_ACCESS_KEY"]

app = FastAPI()


class Credentials(BaseModel):
    username: str
    password: str


@app.get("/")
async def root():
    return {"message": "oh hello there"}


@app.post("/login")
async def login(creds: Credentials):
    c = Cognito(AWS_REGION, AWS_COGNITO_POOL_ID, AWS_COGNITO_CLIENT_ID, AWS_COGNITO_AUTH_FLOW)
    tokens = c.authenticate(creds.username, creds.password)
    # print(tokens)
    return c.verify_tokens(tokens)


if __name__ == "__main__":
    # uvicorn.run("main:app", reload=True, host="0.0.0.0", log_level="info")
    uvicorn.run("main:app", reload=True)
