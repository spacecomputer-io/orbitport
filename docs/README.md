# orbitport docs

This folder contains documentation for `orbitport`.

## Documents

- [Aptos Orbital](APTOS_ORBITAL.md)

## Overview

The Gateway proxies requests to services while providing aggregation and fallback capabilities on top to streamline the integration of space computing services such as randomness generation or TEEs, served by multiple providers to ensure high availability and reliability.

**NOTE:** Altough the gateway is designed to be a simple and modular enough to be easily extended to support new services and providers,
the focus at the moment is on **space randomness** provided by **Aptos Orbital**. 

### API

The API is described in the [openapi spec](../swagger.yml) at the root folder.
You can use [Swagger Editor](https://editor.swagger.io/) to visualize and generate client code.

## Architecture

The following diagram visualizes the architecture of the gateway in the context of randomness:

[![Gateway Architecture](randomness-aptosorbital.png)](randomness-aptosorbital.png)

The gateway has several challenges to overcome to provide a reliable and secure service:

### Authentication

The gateway uses token based authentication where users are provided with a `client-id` and `client-secret` and they use that pair to issue an access token from a given provider.

**Supported Auth Providers**

- [Auth0](https://auth0.com/)

### Aggregation and Throttling

The gateway aggregates requests to the underlying provider, enabling to serve client under limited rate limits and to ensure the entropy of the randomness.

#### Fallback

The gateway supports multiple randomness sources to provide high availability and reliability by switching to another provider in case of failure.

We fallback to local sources in one of the following cases:
- The daily rate limit for aptos was exceeded (`ErrDailyRateLimitExceeded`)
- The rate limits of the gateway (`APTOS_ORBITAL_RATE_LIMIT`) were exceeded (`ErrRateLimitExceeded`)
- Aptos orbital api timeout

#### Randomness Sources

1. **Aptos Orbital** 

Space based randomness provided by `cEDGE` or `Crypto2` satellites.

2. **Local (with random seed from space)**

Randomness using a (space) `master seed` that we fetch continuously from Aptos Orbital. 
Used as primary source for local randomness with go's `math/rand` pkg. Used as fallback if aptos orbital is not available.

3. **Local (Golang crypto pkg)**

Local randomness provided by go's `crypto/rand` pkg. Used as last resort if no other source is available.

