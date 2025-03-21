# orbitport docs

This folder contains documentation for `orbitport`.

## Documents

- [Aptos Orbital](APTOS_ORBITAL.md)

## Overview

Orbitport is a gateway to orbital services such as `cTRNG` (aka cosmic True Random Number Generator) or `spaceTEE`, served by multiple providers to ensure high availability and reliability.

Orbitport provides a unified API to access services from multiple sources, with the ability to switch between them in case of failure. It also performs aggregation and fallbacks in order to streamline the flow of requests and to overcome high loads or downtimes of the underlying sources.

### API

The API is described in the [openapi spec](../swagger.yaml) at the root folder.
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

1. **cosmic/aptos_orbital** 

Space based randomness provided by `cEDGE` or `Crypto2` satellites.

2. **local/cosmic_seed** (cosmic random seed)

Randomness using a (space) `master seed` that we fetch continuously from Aptos Orbital. 
The seed is used to generate more random numbers locally, by using it as a seed for a bip32 master key and deriving keys from it.

**NOTE:** Seed rotation is expected every 1h.

3. **local/go_crypto** (Golang crypto pkg)

Local randomness provided by go's `crypto/rand` pkg. Used as last resort if no other source is available.

