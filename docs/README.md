# Orbitport | Dev Docs

This folder contains internal/dev documentation for Orbitport.


## Overview

Orbitport is SpaceComputer's multi-tenant KMS gateway, exposed through HTTP JSON-RPC and backed by OpenBao.

Orbitport is designed to be straightforward to integrate from web2 and web3 applications while keeping key material within the managed KMS.

### Services

Orbitport currently supports managed cryptographic operations:

#### KMS

The KMS supports Transit encryption, signing, key rotation and data-key generation, Ethereum signing, and post-quantum ML-DSA and ML-KEM operations where enabled by the OpenBao deployment.

## Links

- [Roadmap](ROADMAP.md)
- [Dev Guide](DEV_GUIDE.md)

## External Links

- [Orbitport user guide](https://docs.spacecomputer.io/using-orbitport/user-guide)
- [SpaceComputer docs](https://docs.spacecomputer.io)
