# Web3 backend signing

A backend signs Ethereum messages (here a Sign-In with Ethereum style challenge) with a secp256k1 key in the KMS. The key never sits in app memory, and anyone can recover the signer's address off-chain.

```bash
./run.sh
```

API calls: `kms.GetKeyMetadata` (address), `kms.Sign` (`ETHEREUM_SECP256K1`, `EIP191`) on `examples-eth`.

Recovery uses [Foundry](https://getfoundry.sh) `cast wallet verify` when installed; any EIP-191 verifier works.
