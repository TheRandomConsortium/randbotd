# randbotd 🛡️
### The Decentralized Trust & Multi-Network SSL Authority Daemon

`randbotd` is a peer-to-peer daemon and Web-of-Trust engine designed to bring TLS/SSL transport security to Handshake (`.hns`), Tor (`.onion`), I2P (`.i2p`), and clearnet web infrastructure without relying on legacy ICANN Certificate Authority monopolies (Let's Encrypt, DigiCert, Sectigo, etc.).

---

## 🚀 Core Functionalities

### 1. Root & Intermediate CA Creation (`Publish CA`)
Node operators can publish their own Certificate Authority (CA) on the network:
* **Custom Subject Metadata:** Define Subject Name, Emissor, Organization (O), Organizational Unit (OU).
* **Cryptographic Agility:** Configurable key algorithms (RSA 4096, ECDSA P-384, Ed25519) and signature parameters.
* **Multi-Network Support:** Serves Handshake (`.hns`), Tor (`.onion`), I2P (`.i2p`), and traditional clearnet domains.
* **P2P Propagation:** CAs and public cert chains are broadcast to the network alongside reputation metrics.

### 2. Proof-of-Work (PoW) Ponderated Voting (`Vote TW / UTW`)
Nodes cast votes rating domains and their underlying CAs as **TW** (Trustworthy) or **UTW** (Untrustworthy):
* **1 Node = 1 Vote per Domain:** Prevents basic spamming.
* **PoW Ponderation:** Every vote requires a valid Proof-of-Work challenge.
* **Network Behavior Audit:** The network evaluates node voting patterns. Falsifying PoW or submitting malicious votes results in immediate vote rejection and permanent weighting/reputation penalties against the node.

### 3. ACME-Like Certificate Issuance (`GetCert`)
Domain owners request TLS certificates via an ACME-compatible endpoint:
* **Randomized Allocation:** Certificates are issued at random from a pool of CAs exceeding the network's Trustworthy (TW) threshold.
* **Zero Single Point of Failure:** Prevents targeted revocation or censorship of individual domains by a single CA.

### 4. Proactive Early Warning & Inbox System
* **Domain Owner Notifications:** If a Trustworthy (TW) domain is hosted under a CA that gets flagged as Untrustworthy (UTW), `randbotd` sends an inbox alert recommending early certificate re-issuance under a clean CA pool.
* **CA Operator Notifications:** If a Trustworthy (TW) CA receives an UTW domain strike, `randbotd` sends an inbox alert advising the operator to investigate and revoke the offending certificate.

---

## 🔌 Ecosystem Integration

### Caddy CertMagic Plugin
* A native `randbotd` plugin for Caddy's `certmagic` library, allowing web servers to automatically request, install, and renew Handshake, Onion, Garlic (I2P), and clearnet SSL certificates via `randbotd` ACME endpoints.

### Public Transparency Index (`bullshiters.randºm`)
* A public cryptographic shaming portal indexing non-randbotd domains and Certificate Authorities deemed Untrustworthy (UTW) by network consensus.

---

## 📄 License

Mozilla Public License 2.0 (MPL-2.0). See `LICENSE` for details.
