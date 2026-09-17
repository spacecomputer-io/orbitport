# Orbitport | Roadmap 

Orbitport’s long-term vision is to be a trust-minimized gateway for managed cryptographic operations.

---

## v1 – Centralized Gateway (MVP)

- **Functionality:**  
  - Orbitport operates as a managed gateway to OpenBao-backed KMS capabilities.
  - Only SpaceComputer can deploy and manage the gateway.
  - Provides a unified API for key creation, encryption, signing, and key agreement.
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
- **Managed cryptography:**
  - Critical execution can run in a TEE, enabling verifiable logic and reproducible attestation.
  - KMS operations remain tenant-scoped and key material remains in the KMS.
- **Deployment:**  
  - Multi-cloud, leveraging TEEs for verifiable execution.

---

## v3 – Decentralized & Direct Communication with Space Infrastructure

- **Functionality:**  
  - Anyone meeting requirements can deploy their own Orbitport instance.
  - Focus on removing the gateway as a single point of trust.
  - Enables independently operated, interoperable KMS nodes.
- **Trust Model:**  
  - Decentralized, trust-minimized RPC nodes.
  - Further reduces reliance on any single operator or gateway.
- **Deployment:**  
  - Permissionless, community-driven, and potentially peer-to-peer if deployed as part of a decentralized network.

---
