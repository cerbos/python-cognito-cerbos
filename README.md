# python-cognito-cerbos

An example application of integrating [Cerbos](https://cerbos.dev) with a [FastAPI](https://fastapi.tiangolo.com/) server using [AWS Cognito](https://aws.amazon.com/cognito/) for authentication.

## Dependencies

- Python 3.10
- Docker for running the [Cerbos Policy Decision Point (PDP)](https://docs.cerbos.dev/cerbos/0.6.0/installation/container.html)
- A configured AWS Cognito User Pool ([set-up guide](https://docs.aws.amazon.com/cognito/latest/developerguide/getting-started-with-cognito-user-pools.html))

## Getting Started

1. Start up the Cerbos PDP instance docker container. This will be called by the FastAPI app to check authorization.

```bash
cd cerbos
./start.sh
```

2. Install python dependencies

```bash
# from project root
./pw install
```

3. Set the appropriate environment variables

```bash
AWS_COGNITO_POOL_ID
AWS_COGNITO_CLIENT_ID
AWS_DEFAULT_REGION
AWS_COGNITO_POOL_NAME

# if you've configured your user pool with a client secret
AWS_COGNITO_CLIENT_SECRET

# optionally, to enable the hosted UI:
AWS_COGNITO_HOSTED_UI_CALLBACK_URL # this needs to match the callback URL configured for the hosted UI
AWS_COGNITO_HOSTED_UI_LOGOUT_URL
```

4. Start the FastAPI dev server

```bash
./pw demo
```

## Cognito Configuration

### Groups

This demo maps Cognito User Pool groups to Cerbos roles. The app will retrieve the groups from the access token, and use them to determine authorization.

Any test users in your pool should be added to one or both of `admin` and/or `user` groups to demonstrate different access to the demo resources.

## Policies

This example has a simple CRUD policy in place for a resource kind of `contact` - like a CRM system would have. The policy file can be found in the `cerbos/policies` folder [here](https://github.com/cerbos/python-cognito-cerbos/blob/main/cerbos/policies/contact.yaml).

Should you wish to experiment with this policy, you can <a href="https://play.cerbos.dev/p/g561543292ospj7w0zOrFx7H5DzhmLu2" target="_blank">try it in the Cerbos Playground</a>.

<a href="https://play.cerbos.dev/p/g561543292ospj7w0zOrFx7H5DzhmLu2" target="_blank"><img src="docs/launch.jpg" height="48" /></a>

The policy expects one of two roles to be set on the principal - `admin` and `user`. These roles are authorized as follows:

| Action | User     | Admin |
| ------ | -------- | ----- |
| list   | Y        | Y     |
| read   | Y        | Y     |
| create | Y        | Y     |
| update | If owner | Y     |
| delete | If owner | Y     |
