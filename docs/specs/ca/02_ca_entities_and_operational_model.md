# 📜 `randbotd` CA Entities & Operational Architecture
### *Part 2: CA Data Model, Custodian Governance, Distributed Swarms, Multi-Tier Catalogs & Verification Sovereignty*

---

## 3. CA Entity Data Model & Operational Architecture

A Certificate Authority in `randbotd` is NOT merely a static cryptographic keypair. It is a **sovereign P2P network entity** with an identity, custodian governance model, multi-tier offer catalog, operational risk boundaries, consensus state, and anti-entropy event log integration.

```
+-----------------------------------------------------------------------------------+
|                                 CA Entity Data Model                              |
+-----------------------------------------------------------------------------------+
| 1. Cryptographic Identity & Custodian                                             |
|    - ca_id: Hash(CA Root PubKey)                                                  |
|    - custodian_type: SingleNode | DistributedSwarm (FROST m-of-n)    [CA-11]       |
|    - active_custodian_nodes: Vec<NodePubKey>                                      |
+-----------------------------------------------------------------------------------+
| 2. Multi-Tier Offer Catalog                                                       |
|    - catalog_id: Hash(CAPublishOfferCatalog)                         [CA-12]       |
|    - profiles: Vec<CertificateProfile>                                            |
|        * Profile 0: Free Tier (0 XMR, 30-90d TTL, Single SAN)        [PAY-05]      |
|        * Profile 1: Multi-SAN / Wildcard (0.005 XMR, 180d TTL)       [PAY-01]      |
|        * Profile 2: Long-TTL / Enterprise (0.02 XMR, 365d TTL)       [CA-08]       |
+-----------------------------------------------------------------------------------+
| 3. Operational & Risk Parameters                                                  |
|    - risk_floor_threshold: Percentage (e.g. 45.0%)                  [ACME-05]     |
|    - proof_backends: Bitmask (DNS, Handshake, Tor, I2P, Nonce)       [CA-03]       |
|    - max_issuance_rate: u32 (Certs / Epoch)                                       |
+-----------------------------------------------------------------------------------+
| 4. Reputation, Consensus State & History                                          |
|    - baseline_trust_score: 50.0%                                     [ACME-02]     |
|    - p75_ensemble_vote_count: u64                                    [ACME-04]     |
|    - confidence_window_delta: +/- Delta                              [ACME-04]     |
|    - distrust_strikes: Vec<DistrustStrike>                           [REP-09]      |
|    - key_rotation_history: Vec<KeyRotationProof>                     [CA-09]       |
|    - p2p_sequence_binding: (seq, prev_hash)                          [NET-05]      |
+-----------------------------------------------------------------------------------+
```

---

### 3.0 Unix Domain Socket IPC Administration & Local Node Control

In a systemd managed installation (`StateDirectory=randbotd`), `randbotd` enforces strict state directory isolation (`/var/lib/randbotd` mode `0750`). Direct daemon administration commands over the Unix domain socket (`/var/lib/randbotd/randbotd.sock`) require administrative privileges using `sudo socat`:

```bash
# Publish Root CA via daemon Unix Domain Socket (sudo socat)
echo '{"PublishCa":{"common_name":"The Random Consortium Root CA","organization":"The Random Consortium","organizational_unit":"PKI Operations","locality":"Valencia","state_or_province":"Valencia","country":"ES","email":"ca@therandomconsortium.org","is_intermediate":false,"path_len_constraint":null}}' | sudo socat - UNIX-CONNECT:/var/lib/randbotd/randbotd.sock
```

> **Security Note**: Direct IPC socket access enforces strict system administrative authorization (`sudo` or `randbotd` user group membership), protecting private keys and the transactional event log database.

---

### 3.1 Custodian Identity & Multi-Node Distributed Architecture

A CA is originally registered by a **Custodian**—the initial node operator who emits the `CAPublishDeclaration` event into the P2P log (`NET-04`/`NET-05`). `randbotd` supports a two-phase custodian architecture:

#### Phase 1: Single Node Custodian (Initial Registration)
- The CA identity (`ca_id`) is derived deterministically from the owner node's P2P public key and common name.
- The single creating node signs all CA management declarations (`CAPublishOfferCatalog`, domain purges `CA-07`, key rotations `CA-09`).
- Signing certs is executed directly by the node's local key store.

#### Phase 2: Distributed Custodian Swarm Model (`CA-11`)
To distribute operational load, prevent server downtime, and protect high-reputation CAs against single-node key theft, `randbotd` establishes the **Distributed Custodian Swarm Engine**:
1. **Threshold Cryptography (FROST / $m$-of-$n$ Schnorr/Ed25519 / ECDSA DKG)**: A CA identity key is generated collectively via **Distributed Key Generation (DKG)** across $n$ custodian nodes without ever assembling the full secret key on a single machine. Any $m$ out of $n$ custodian nodes collaborate to emit a valid certificate.
2. **Parallel ACME Load-Sharing Protocol**: Domain certificate issuance requests arriving at the CA endpoint are load-balanced across active custodian swarm nodes.

#### 4-Step Escrow-Less Custodian Delegation State Machine (`CA-11`)

```
Worker Node                                 CA Node                               P2P Swarm
    |                                          |                                      |
    |---- 1. CustodianContract --------------->|                                      |
    |     (CA_ID, Max TTL, WorkShare % P_w)    |                                      |
    |                                          |                                      |
    |<--- 2. CustodianDelegationRequest -------|                                      |
    |     (Accords terms, targets Worker)      |                                      |
    |                                          |                                      |
    |---- 3. CACapabilitiesProof -------------->|                                      |
    |     (Dummy Cert Build, Liveness Proof)   |                                      |
    |                                          |                                      |
    |<--- 4. SwarmActivationConfirmation ------|                                      |
    |     (CA signs final swarm entry)         |                                      |
    |                                          |                                      |
    |=================== 5. Swarm Admission & P2P Validation ==========================>|
    |                    (Verified locally network-wide; 0 Upfront Fee)                |
    |                                                                                 |
    |---- (Per-Issuance Pay-As-You-Work Revenue-Share Settlement under PAY-03) ------->|
    |     (Monero tx_key routes P_w % to active m co-signers upon cert emission)       |
```

1. **Step 1: `CustodianContract`**: Candidate worker node publishes signed contract with work-share percentage $P_{\text{worker}}$.
2. **Step 2: `CustodianDelegationRequest`**: CA node confirms accord terms.
3. **Step 3: `CACapabilitiesProof`**: Candidate proves working crypto and verification backends via a signed dummy build.
4. **Step 4: `SwarmActivationConfirmation`**: CA emits final quorum admission.
5. **Step 5: Trustless Pay-As-You-Work Settlement**: Monero `tx_key` splits per-issuance fees to active co-signers.

---

### 3.2 Economic Model: Single Offer vs. Multi-Tier Offer Catalog (`CA-12`)

A single static pricing model excludes either free domains or premium users. `randbotd` implements a structured **Offer Catalog** (`CAPublishOfferCatalog`):

```
+------------------------------------------------------------------------------------+
|                         CA Certificate Offer Catalog Structure                     |
+------------------------------------------------------------------------------------+
| Catalog Meta: CA_ID | Catalog Version | Timestamp | Custodian Signature            |
+------------------------------------------------------------------------------------+
| Profile 0: "Standard Free Tier"                                                   |
|   - Price: 0.0000 XMR  (Free-Only Compatible)                                     |
|   - Supported Proofs: DNS TXT, HTTP Nonce                                          |
|   - Allowed Keys: RSA-4096, ECDSA P-384, Ed25519                                  |
|   - Max TTL: 90 Days | SAN Limit: 1 Single Domain                                 |
+------------------------------------------------------------------------------------+
| Profile 1: "Multi-Domain SAN & Wildcard Tier"                                     |
|   - Price: 0.0050 XMR                                                              |
|   - Supported Proofs: DNS TXT, Handshake HNS, Tor ALPN, I2P LeaseSet               |
|   - Allowed Keys: RSA-4096, ECDSA P-384, Ed25519                                  |
|   - Max TTL: 180 Days | SAN Limit: Up to 100 SAN Domains (Wildcards)               |
+------------------------------------------------------------------------------------+
| Profile 2: "Long-TTL Enterprise Tier"                                             |
|   - Price: 0.0200 XMR                                                              |
|   - Supported Proofs: All Multi-Network Backends                                   |
|   - Allowed Keys: All Algorithms (Including Post-Quantum ML-DSA-44)                 |
|   - Max TTL: 365 Days | SAN Limit: Unlimited                                       |
+------------------------------------------------------------------------------------+
```

---

### 3.3 Operational Parameters & Risk Boundaries

1. **CA Operator Risk Floor Threshold (`ACME-05`) — Downward-Only Risk Amplification**:
   - A CA operator can configure a custom `risk_floor` acceptance threshold (e.g. 35.0%).
   - **Anti-Domain-Fishing Rule**: This threshold **ONLY permits downward risk expansion below the CA's dynamic lower confidence bound ($50\% - \Delta_{\text{CA}}$)**. CAs cannot artificially raise floors to cherry-pick safe domains.
2. **Multi-Network Proof Backends (`CA-03`)**: Bitmask declaring active backends (`DNS_TXT`, `HANDSHAKE_HNS`, `TOR_ALPN`, `I2P_LEASESET`, `HTTP_NONCE`).
3. **Issuance Rate Limiting**: Capped certificate emissions per epoch to prevent resource exhaustion.

---

### 3.4 Consensus State, Reputation & Anti-Entropy Event Log Binding

Every CA is tracked in the immutable `randbotd` P2P event log (`NET-04`/`NET-05`):
- **Baseline 50% Initializer (`ACME-02`)**: Starts at 50% with $\Delta_{\text{CA}} = \pm 50\%$.
- **Logarithmic Confidence Window (`ACME-04`)**: Dynamic window derived from the P75 domain vote ensemble.
- **Distrust Strike Accumulator (`REP-09`)**: Permanent records of market distrust strikes.
- **Key Rotation Ledger (`CA-09`)**: Audit trail of `KeyRotationProof` events.

---

### 3.5 Local Node Verification Sovereignty & Anti-Solipsism

In `randbotd`, **no CA declaration, certificate emission, extension payload, or revocation assertion is trusted at face value**:
- **Independent Verification**: Every node verifies every gossip payload (proof signatures, Monero `tx_key` payment proofs, and ASN.1 WoT extensions).
- **Solipsistic Isolation for Dishonest CAs**: If a CA emits a fraudulent purge or fake payment proof, peer nodes discard the log event. The lying CA exists in a solipsistic parallel state while suffering reputation penalties network-wide.
