# Orbitport Guides

## Table of Contents

- [API Usage (v0.1)](#api-usage-v01)
  - [Authentication](#authentication)
  - [Randomness endpoint](#randomness-endpoint)

## API Usage (v0.1)

**version:** `v0.1`

To view the api spec use https://editor-next.swagger.io/ and import the swagger file:
`https://gist.githubusercontent.com/amirylm/23ba4bd1a289572c1331fd10750cb5b5/raw/4b77f5396874c5c35a49b0ef837567adf2e07194/swagger.yaml`

### Authentication

Get access token from auth0:

```bash
# export OP_AUTH_URL=dev-1usujmbby8627ni8.us.auth0.com
curl --request POST --url "https://${OP_AUTH_URL}/oauth/token" \
  --header 'content-type: application/json' \
  --data '{"client_id":"'"${OP_CLIENT_ID}"'","client_secret":"'"${OP_CLIENT_SECRET}"'","audience":"https://op.spacecoin.xyz/api","grant_type":"client_credentials"}' \
 | jq -r '.access_token'
```

### Randomness endpoint

**NOTE:** see openapi spec below for detailed information

```bash
curl --request GET --url https://op.spacecoin.xyz/api/v1/rand_seed \
  --header "authorization: Bearer ${ACCESS_TOKEN}"