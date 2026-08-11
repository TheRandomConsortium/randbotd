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

### 2. Lazy Evaluation & Weighted Reputation Engine (`Vote TW / UTW`)
Nodes cast votes rating domains as **TW** (Trustworthy) or **UTW** (Untrustworthy), which are lazily evaluated upon network query:
* **1 Active Vote per Node (Dynamic Mind-Changing)**: Each node holds exactly 1 active vote per domain to prevent vote-stuffing. However, a node can change its mind at any time (e.g. flipping a vote from UTW to TW if a domain reforms, or vice-versa).
* **PoW & Node Behavior Ponderation**: Every vote requires a valid Proof-of-Work challenge and is weighted against the voting node's historical behavior score. Malicious review-bomber nodes lose voter reputation, neutralizing their voting power across the network.
* **CA Rating Propagation**: A Certificate Authority's reputation score is calculated dynamically as the **weighted average of the trust scores of all domains issued under its authority**.
* **Bi-Directional Image Cleaning**:
  * **CA Image Cleaning**: A CA can clean and elevate its overall network reputation by actively revoking/banning UTW domains hosted under its certificates.
  * **Domain Image Cleaning**: A domain elevates its reputation score by acquiring positive TW votes or when malicious UTW review-bomber nodes lose voter weight.

### 3. Fair-Band ACME Certificate Allocation (`GetCert`)
Domain owners request TLS certificates via an ACME-compatible endpoint:
* **50% Baseline Initialization**: Newly registered domains and CAs initialize at a neutral **50% baseline score** with 0 votes ($\Delta = \pm 50\%$).
* **Randomized Fair-Band Matching ($\pm \Delta$)**: Rather than assigning a fixed CA, `GetCert` randomly selects a Certificate Authority from the pool of CAs whose reputation score matches the domain's score within a dynamic confidence window ($\pm \Delta$).
* **Logarithmic Dynamic Confidence Engine ($\Delta$)**: The tolerance window ($\Delta$) decays along a logarithmic curve starting from $\pm 50\%$ as vote volume increases relative to total active network nodes ($N_{\text{active\_nodes}}$):
  * **Domain $\Delta$**: $\Delta_{\text{domain}} = \pm 50\% \times f\left(\frac{N_{\text{votes}}}{N_{\text{active\_nodes}}}\right)$, dropping rapidly at first and narrowing toward the domain's true consensus rating.
  * **CA Ensemble $\Delta$**: Evaluated across the ensemble of domains issued under the CA using the 75th percentile (P75) vote volume: $\Delta_{\text{CA}} = \pm 50\% \times f\left(\frac{\text{P75}(\{N_{\text{votes}}(\text{domain}_i)\})}{N_{\text{active\_nodes}}}\right)$.
  * **Boundary Clipping & Non-Negative Floor**: Scores are strictly clipped to $[0\%, 100\%]$ and $\Delta \ge 0$.
  * **Dynamic Lazy-Evaluation Expansion**: On lazy evaluation, as total active nodes ($N_{\text{active\_nodes}}$) expand, $\Delta$ naturally widens for stale entities until new votes solidify their position.
* **CA-Configurable Risk Floor**: A CA operator may voluntarily lower their minimum accepted reputation threshold (e.g. opting to issue certificates to unproven or lower-tier 10%–49% domains). This allows CAs to host high-risk or radical censorship-resistant domains willingly, while taking on the risk that hosting UTW domains will lower the CA's overall public rating.

### 4. Proactive Early Warning & Inbox System
* **Domain Owner Notifications:** If a Trustworthy (TW) domain is hosted under a CA that gets flagged as Untrustworthy (UTW), `randbotd` sends an inbox alert recommending early certificate re-issuance under a clean CA pool.
* **CA Operator Notifications:** If a Trustworthy (TW) CA receives an UTW domain strike, `randbotd` sends an inbox alert advising the operator to investigate and revoke the offending certificate.

---

## 🛠️ Operational Administration & Daemon Control

In a systemd managed installation, `randbotd` enforces strict state directory isolation (`/var/lib/randbotd` mode `0750`). Daemon control commands sent via the Unix domain socket (`/var/lib/randbotd/randbotd.sock`) must be executed with `sudo` using `socat` (or by users in the `randbotd` group):

### 1. Publishing a Certificate Authority (`PublishCa`)
```bash
echo '{"PublishCa":{"common_name":"The Random Consortium Root CA","organization":"The Random Consortium","organizational_unit":"PKI Operations","locality":"Valencia","state_or_province":"Valencia","country":"ES","email":"ca@therandomconsortium.org","is_intermediate":false,"path_len_constraint":null}}' | sudo socat - UNIX-CONNECT:/var/lib/randbotd/randbotd.sock
```

### 2. Importing a Peer (`ImportPeer`)
```bash
echo '{"ImportPeer":{"peer_addr":"85.52.85.114:43210"}}' | sudo socat - UNIX-CONNECT:/var/lib/randbotd/randbotd.sock
```

> **Security Note**: Direct Unix socket commands strictly enforce system administrative authorization (`sudo` or `randbotd` group membership).

---

## 🔌 Ecosystem Integration

### Caddy CertMagic Plugin
* A native `randbotd` plugin for Caddy's `certmagic` library, allowing web servers to automatically request, install, and renew Handshake, Onion, Garlic (I2P), and clearnet SSL certificates via `randbotd` ACME endpoints.

### Public Transparency Index (`bullshiters.randºm`)
* A public cryptographic shaming portal indexing non-randbotd domains and Certificate Authorities deemed Untrustworthy (UTW) by network consensus.

---

## 📄 License

Mozilla Public License 2.0 (MPL-2.0). See `LICENSE` for details.
