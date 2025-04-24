# Orbitport: User Guide

**version:** `v0.2`

## Table of Contents

- [Authentication](#authentication)
- [API Usage (v0.2)](#api-usage-v02)
  - [cTRNG](#ctrng)

## Authentication

You need to get an access token from auth0 for interacting with the API.

1. Get credentials

```bash
OP_AUTH_URL=dev-1usujmbby8627ni8.us.auth0.com
OP_CLIENT_ID=<your-client-id>
OP_CLIENT_SECRET=<your-client-secret>
```

2. Get access token from auth0:

```bash
curl --request POST --url "https://${OP_AUTH_URL}/oauth/token" \
  --header 'content-type: application/json' \
  --data '{"client_id":"'"${OP_CLIENT_ID}"'","client_secret":"'"${OP_CLIENT_SECRET}"'","audience":"https://op.spacecomputer.io/api","grant_type":"client_credentials"}' \
 | jq -r '.access_token'
```

## API Usage

### cTRNG

To make a trng request, run the following command:

```bash
curl --request GET --url https://op.spacecomputer.io/api/v1/services/trng \
  --header "authorization: Bearer ${ACCESS_TOKEN}"
```

#### Example Response

```json
{
  "service": "trng",
  "src": "aptosorbital",
  "data": "0a4c2ea21557418bbc1d57120142ad83e8fa6e030ad35125fe225b97929d2526",
  "signature": {
    "value": "3046022100da9e9dfbe4167da1bd7b824ab46e57506cfbebc50395fdf0bb3d3407c1d92451022100e33601c04b402fc57d8ffd22d41b01ec5315d4e1a1d2be97bf71323cc5cc3838",
    "pk": "",
    "algo": ""
  }
}
```

#### Parameters

- `src`: The source of the random number. Can be `trng` or `rng`.

#### Randomness Sources

The gateway supports multiple sources of randomness.
The desired sources can be specified (by order) with `src` query parameter, e.g. `?src=aptosorbital&src=...&src=...`

Default is `[aptosorbital,derived]`, i.e. try to get a TRN from a satellite or fallback to TRN derived from a TRN that was fetched previously.

Available sources are:
1. **aptosorbital**: Space based randomness provided by `cEDGE` or `Crypto2` satellites.

2. **derived** (from cosmic random seed): Randomness derived from a cTRNG (aka `master seed`) that is fetched continuously. The seed is used to generate more random numbers when aptos-orbital's satellites are not responsive, by using it as a seed for a bip32 master key and deriving keys from it.

