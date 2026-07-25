# Orbitport | Roadmap 

Orbitport’s long-term vision is to be a trust-minimized gateway for secure, verifiable communication with space infrastructure.

---

## v1 – Centralized Gateway (MVP)

- **Functionality:**  
  - Orbitport operates as an on-Earth gateway to upstream space infrastructure, beginning with the Crypto2 API.
  - Only SpaceComputer can deploy and manage the gateway.
  - Provides unified API for orbital services (e.g., cTRNG, spaceTEE).
- **Trust Model:**  
  - Trust is placed in SpaceComputer’s operations and infrastructure.
- **Deployment:**  
  - Centralized, managed by SpaceComputer.

---

## v2 – Trust-Minimized Gateway

- **Functionality:**  
  - Orbitport is deployed across multiple TEE (Trusted Execution Environment) cloud providers.
  - Strategic partnerships to increase decentralization and resilience.
- **Trust Model:**  
  - Trust is minimized:  
    - Critical parts run in a TEE, enabling verifiable logic and reproducible attestation.
    - Open-source codebase allows public verification of logic.
- **End-to-end Encryption:**
  - Messages are encrypted and signed on the satellite.
  - Decryption and processing occur in TEE-based Orbitport, then securely delivered to customers.
- **Verifiable Randomness:**  
  - Allow users to verify that the random number is originated from the satellite, not from an untrusted source on earth.
- **Deployment:**  
  - Multi-cloud, leveraging TEEs for verifiable execution.

---

## v3 – Decentralized & Direct Communication with Space Infrastructure

- **Functionality:**  
  - Anyone meeting requirements can deploy their own Orbitport instance.
  - Focus on removing the on-Earth gateway as a single point of trust.
  - Enables direct communication with space infrastructure (e.g., via Iridium terminals).
- **Trust Model:**  
  - Decentralized, trust-minimized RPC nodes.
  - Further reduces reliance on any single operator or gateway.
- **Verifiable Randomness:**  
  - Allow users to verify that the random number is truly random / to verify the entropy of the randomness.
- **Deployment:**  
  - Permissionless, community-driven, and potentially peer-to-peer if deployed as part of a decentralized network.

---
