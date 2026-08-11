# 📜 `randbotd` CA Entities & Certificate Specification
### *Complete X.509 v3 Attribute Mapping, CA Custodian Architecture, Multi-Tier Offer Catalogs & International Standards Alignment*

---

## 📑 Table of Contents

1. [Executive Summary & Architectural Context](#1-executive-summary--architectural-context)
2. [Complete TLS Certificate Field Investigation & Mapping Matrix](#2-complete-tls-certificate-field-investigation--mapping-matrix)
   - [2.1 Standard X.509 v3 Certificate Header Fields (RFC 5280 §4.1)](#21-standard-x509-v3-certificate-header-fields-rfc-5280-41)
   - [2.2 Standard X.509 v3 Extensions (RFC 5280 §4.2)](#22-standard-x509-v3-extensions-rfc-5280-42)
   - [2.3 `randbotd` Custom & Web-of-Trust Extensions](#23-randbotd-custom--web-of-trust-extensions)
   - [2.4 IEEE 1609.2 & Specialized PKI Certificate Attributes](#24-ieee-16092--specialized-pki-certificate-attributes)
3. [CA Entity Data Model & Operational Architecture](#3-ca-entity-data-model--operational-architecture)
   - [3.1 Custodian Identity & Multi-Node Distributed Architecture](#31-custodian-identity--multi-node-distributed-architecture)
   - [3.2 Economic Model: Single Offer vs. Multi-Tier Certificate Offer Catalog](#32-economic-model-single-offer-vs-multi-tier-certificate-offer-catalog)
   - [3.3 Operational Parameters & Risk Boundaries](#33-operational-parameters--risk-boundaries)
   - [3.4 Consensus State, Reputation & Anti-Entropy Event Log Binding](#34-consensus-state-reputation--anti-entropy-event-log-binding)
4. [Comprehensive Standards Reference Matrix](#4-comprehensive-standards-reference-matrix)
5. [Newly Proposed Functionalities for `FUNCTIONALITIES.md`](#5-newly-proposed-functionalities-for-functionalitiesmd)

---

## 1. Executive Summary & Architectural Context

In traditional Public Key Infrastructure (PKI), Certificate Authorities (CAs) act as centralized, opaque issuers whose certificate profiles and internal metadata are tightly dictated by browser vendor cartels (CA/Browser Forum Baseline Requirements). In `randbotd`, Public Key Infrastructure is reimagined as a **decentralized, peer-evaluated Web-of-Trust (WoT) consensus engine**. 

To deliver complete cryptographic sovereignty, multi-network domain equality (supporting clearnet, Handshake `.hns`, Tor `.onion`, and I2P `.i2p`), and cypherpunk market dynamics, `randbotd` requires a precise, exhaustive specification of:
1. **Configurable Certificate Parameters**: Every standard field, X.509 extension, custom OID, and handshake attribute present in modern TLS certificates.
2. **CA Entity Properties**: All data structures, operational boundaries, custodian identities, load-sharing mechanisms, and pricing offer models that define a CA node within the P2P swarm.
3. **International Standards Alignment**: Concrete cross-references to official IETF RFCs, ITU-T recommendations, IEEE standards, and CA/Browser Forum guidelines.

This document establishes the authoritative blueprint for `CA-01` (**Custom Subject Metadata Engine**) and its foundational integration with the broader `randbotd` ecosystem.

---

## 2. Complete TLS Certificate Field Investigation & Mapping Matrix

An X.509 v3 certificate (RFC 5280) consists of a signed payload (`TBSCertificate`), a signature algorithm identifier, and a digital signature emitted by the issuing CA key. Below is an exhaustive breakdown of all configurable attributes, their standards references, and their explicit mapping to `randbotd` feature modules.

```
       +-------------------------------------------------------+
       |                  X.509 v3 Certificate                 |
       +-------------------------------------------------------+
       | TBSCertificate:                                       |
       |   - Version (v3)                        [CA-05]       |
       |   - Serial Number (64-160 bit Entropy)  [CA-13] *NEW* |
       |   - Signature Algorithm OID             [CA-02]       |
       |   - Issuer DN (C, O, OU, CN...)         [CA-01]       |
       |   - Validity Period (notBefore/notAfter)[CA-08]       |
       |   - Subject DN (C, O, OU, CN...)        [CA-01]       |
       |   - SubjectPublicKeyInfo (RSA/EC/Ed)    [CA-02]       |
       |   - Extensions:                                       |
       |       * Basic Constraints               [CA-01/05]    |
       |       * Key Usage & EKU                 [CA-05]       |
       |       * Subject Alternative Name (SAN)  [CA-03/05]    |
       |       * Name Constraints (Subtrees)     [CA-14] *NEW* |
       |       * Authority/Subject Key ID        [CA-05]       |
       |       * CRL Distribution Points (CDP)   [CA-04/07]    |
       |       * Authority Info Access (AIA/OCSP)[CA-15] *NEW* |
       |       * Critical WoT OID (2.25.332...)  [CA-10]       |
       |       * Domain Proof Binding Extension  [CA-03]       |
       +-------------------------------------------------------+
       | Signature Algorithm OID                 [CA-02]       |
       | CA Digital Signature (RSA/ECDSA/Ed25519)[CA-02/05]   |
       +-------------------------------------------------------+
```

---

### 2.1 Standard X.509 v3 Certificate Header Fields (RFC 5280 §4.1)

| Field Name | ASN.1 / Data Structure | Configurable Parameters & Options | Standards Reference | Existing / Proposed Feature ID | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **Version** | `INTEGER { v1(0), v2(1), v3(2) }` | Standardized to `v3` (2). Mandatory for extension support. | RFC 5280 §4.1.2.1 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Serial Number** | `CertificateSerialNumber ::= INTEGER` | Cryptographically random integer (minimum 64 bits, up to 160 bits of entropy). Prevents collision and certificate forgery attacks (e.g. Flame collision attacks). | RFC 5280 §4.1.2.2, CABF BR §7.1.4.2.1 | **`CA-13` (Cryptographic Serial Entropy Engine)** | 🆕 Proposed |
| **Signature Algorithm Identifier** | `AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }` | OID and parameters for the issuing CA signature. Supported: RSA-PSS/PKCS#1 v1.5, ECDSA (secp256r1, secp384r1, secp521r1), Ed25519 (pure Ed25519 / RFC 8032), and Post-Quantum algorithms (ML-DSA / Falcon). | RFC 5280 §4.1.2.3, RFC 8032, RFC 5480, NIST SP 800-57 | `CA-02` (Cryptographic Agility Suite) | 🔴 |
| **Issuer Distinguished Name (Issuer DN)** | `Name ::= CHOICE { RDNSequence }` | Distinguished Name of the issuing CA. Configurable fields: Country (`C`), State/Province (`ST`), Locality (`L`), Organization (`O`), Organizational Unit (`OU`), Common Name (`CN`), Email. | RFC 5280 §4.1.2.4, ITU-T X.500 | `CA-01` (Custom Subject Metadata Engine) | 🔴 |
| **Validity Period** | `Validity ::= SEQUENCE { notBefore Time, notAfter Time }` | Time window during which the certificate is cryptographically valid. Expressed in `UTCTime` or `GeneralizedTime`. Supports custom short/long TTLs (1 day to 825 days) and ephemeral micro-TTLs for fallback issuance. | RFC 5280 §4.1.2.5, CABF BR §6.3.2 | `CA-08` (Configurable Cert Parameters / Custom TTL), `ACME-06` (Emergency Default Fallback) | 🔴 |
| **Subject Distinguished Name (Subject DN)** | `Name ::= CHOICE { RDNSequence }` | Distinguished Name of the certificate owner. Configurable fields: Country (`C`), Locality (`L`), Organization (`O`), Organizational Unit (`OU`), Common Name (`CN`), SerialNumber, Pseudonym. Can be left empty if SAN extension is marked critical. | RFC 5280 §4.1.2.6, ITU-T X.500 | `CA-01` (Custom Subject Metadata Engine) | 🔴 |
| **Subject Public Key Info** | `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }` | Encapsulates the public key of the subject node/domain. Configurable key algorithms (RSA 2048/4096, ECDSA P-256/P-384/P-521, Ed25519) and key bits. | RFC 5280 §4.1.2.7, RFC 5480, RFC 8032 | `CA-02` (Cryptographic Agility Suite), `CA-05` (X.509 Builder) | 🔴 |
| **Issuer Unique ID / Subject Unique ID** | `UniqueIdentifier ::= BIT STRING` | Optional X.509 v2/v3 fields used to resolve name reuse. Deprecated in modern PKI but supported in builder parsing. | RFC 5280 §4.1.2.8 | `CA-05` (X.509 Certificate Builder) | 🔴 |

---

### 2.2 Standard X.509 v3 Extensions (RFC 5280 §4.2)

| Extension Name | Extension OID | Criticality | Configurable Parameters & Purpose | Standards Reference | Existing / Proposed Feature ID | Status |
| :--- | :--- | :---: | :--- | :--- | :--- | :---: |
| **Basic Constraints** | `2.5.29.19` | `TRUE` (for CA) / `FALSE` (End-Entity) | `cA` (BOOLEAN: `TRUE` for Root/Intermediate CAs, `FALSE` for leaf certs), `pathLenConstraint` (INTEGER: max depth of downstream CA chains). | RFC 5280 §4.2.1.9 | `CA-01` (Metadata Engine), `CA-05` (X.509 Builder) | 🔴 |
| **Key Usage** | `2.5.29.15` | `TRUE` | Bitmask defining cryptographic key purpose: `digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign` (CA signing), `cRLSign` (CRL signing), `encipherOnly`, `decipherOnly`. | RFC 5280 §4.2.1.3 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Extended Key Usage (EKU)** | `2.5.29.37` | `TRUE` or `FALSE` | Key purpose OIDs: `serverAuth` (`1.3.6.1.5.5.7.3.1`), `clientAuth` (`1.3.6.1.5.5.7.3.2`), `codeSigning` (`1.3.6.1.5.5.7.3.3`), `emailProtection`, `timeStamping`, `ocspSigning`. | RFC 5280 §4.2.1.12 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Subject Alternative Name (SAN)** | `2.5.29.17` | `FALSE` (or `TRUE` if Subject DN empty) | `GeneralNames` sequence binding identities to cert: `dNSName` (clearnet, Handshake `.hns`, wildcards `*.example.hns`), `iPAddress` (IPv4/v6), `uniformResourceIdentifier` (Tor `.onion`, I2P `.i2p` LeaseSets), `rfc822Name` (email), `registeredID`. | RFC 5280 §4.2.1.6, RFC 8555 §7.4 | `CA-03` (Multi-Network Domain Proofs), `CA-05` (X.509 Builder) | 🔴 |
| **Name Constraints** | `2.5.29.30` | `TRUE` | Restricted subtree scope for Intermediate CAs: `permittedSubtrees` and `excludedSubtrees` (e.g. limiting an Intermediate CA strictly to `.hns` or `.onion` domains). | RFC 5280 §4.2.1.10 | **`CA-14` (Subtree Name Constraints Engine)** | 🆕 Proposed |
| **Certificate Policies** | `2.5.29.32` | `FALSE` | Sequence of policy OIDs, Certification Practice Statement (CPS) URIs, and User Notices describing CA issuance policies and legal/operational terms. | RFC 5280 §4.2.1.4 | `CA-05` (X.509 Builder), `PAY-01` (Service Fee Publisher) | 🔴 |
| **Policy Mappings** | `2.5.29.33` | `TRUE` or `FALSE` | Maps issuer domain policy OIDs to subject domain policy OIDs in cross-certifying intermediate CAs. | RFC 5280 §4.2.1.5 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Authority Key Identifier (AKI)** | `2.5.29.35` | `FALSE` | Identifies the public key corresponding to the private key used to sign the cert. SHA-1/SHA-256 key identifier hash or issuer name + serial number sequence. | RFC 5280 §4.2.1.1 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Subject Key Identifier (SKI)** | `2.5.29.14` | `FALSE` | SHA-1/SHA-256 hash of the subject public key. Essential for constructing certificate validation chains. | RFC 5280 §4.2.1.2 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **CRL Distribution Points (CDP)** | `2.5.29.31` | `FALSE` | URIs (`http://`, `randbotd://` P2P URIs) pointing to Certificate Revocation Lists emitted by the CA. | RFC 5280 §4.2.1.13 | `CA-04` (P2P Cert Chain Broadcasting), `CA-07` (Bad-Domain Purge) | 🔴 |
| **Authority Information Access (AIA)** | `1.3.6.1.5.5.7.1.1` | `FALSE` | Access descriptors: `id-ad-ocsp` (OCSP responder URIs) and `id-ad-caIssuers` (URIs to fetch parent CA certificates). In `randbotd`, augmented by P2P swarm queries. | RFC 5280 §4.2.2.1, RFC 6960 | **`CA-15` (P2P AIA & OCSP Extension Engine)** | 🆕 Proposed |
| **Subject Information Access (SIA)** | `1.3.6.1.5.5.7.1.11` | `FALSE` | Access descriptors for details about the subject (e.g. repository locations, validation endpoints). | RFC 5280 §4.2.2.2 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Policy Constraints** | `2.5.29.36` | `TRUE` | `requireExplicitPolicy` and `inhibitPolicyMapping` constraints for path validation. | RFC 5280 §4.2.1.11 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Inhibit Any Policy** | `2.5.29.54` | `TRUE` | Prevents matching `anyPolicy` OID (`2.5.29.32.0`) in certificate validation paths. | RFC 5280 §4.2.1.14 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Signed Certificate Timestamps (SCT)** | `1.3.6.1.4.1.11129.2.4.2` | `FALSE` | Serialized SCT proofs from Certificate Transparency (CT) logs. Replaced/augmented in `randbotd` by P2P Merkle sequence inclusion proofs (`seq`, `prev_hash`). | RFC 6962 §3.3 | `NET-05` (Catch-Up & Anti-Entropy), `CA-04` (P2P Broadcast) | 🟢 / 🔴 |

---

### 2.3 `randbotd` Custom & Web-of-Trust Extensions

| Extension Name | Extension OID | Criticality | Purpose & Cryptographic Behavior | Standards Reference | Feature ID | Status |
| :--- | :--- | :---: | :--- | :--- | :--- | :---: |
| **Critical WoT Validation Extension** | `2.25.332006307751889903095271628869501346770.1.1` | `TRUE` | Derived from ITU-T X.667 UUID `f9c616c7-8e4d-4f84-a32e-596b5ada63d2`. Enforces voluntary opt-in (un-augmented legacy browsers reject the cert), prevents free-riding, and neutralizes stolen/unpaid certificates outside P2P consensus. | ITU-T X.667 / RFC 5280 §4.2 | `CA-10` (WoT Critical OID Extension) | ⚪ |
| **Domain Proof Binding Extension** | Custom `randbotd` OID (`2.25.332006307751889903095271628869501346770.1.2`) | `FALSE` | Embeds the cryptographic proof signature (DNS TXT record hash, Handshake record signature, Tor ALPN proof, or HTTP Nonce signature) validating domain control at issuance time. | RFC 8555, `randbotd` Spec | `CA-03` (Multi-Network Domain Proofs) | 🔴 |
| **Out-of-Net Classification Tag** | Custom `randbotd` OID (`2.25.332006307751889903095271628869501346770.1.3`) | `FALSE` | Mandatory tag isolating self-signed, Caddy internal, or legacy ICANN certificates ingested into the local node trust store from native peer-voted `randbotd` CAs. | `randbotd` Manifesto §3.4 | `OUT-03` (`out-of-net` Cryptographic Marking) | 🔴 |
| **Monero Settlement Binding (`TxKeyProof`)** | Custom `randbotd` OID (`2.25.332006307751889903095271628869501346770.1.4`) | `FALSE` | Binds the certificate digest to the Monero `tx_key` and contract constitution hash, enabling P2P nodes to verify fee settlement on-chain without third-party escrow. | `randbotd` Manifesto §3.5 | `PAY-03` (3-Step Escrow-less Settlement) | 🔴 |

---

### 2.4 IEEE 1609.2 & Specialized PKI Certificate Attributes

While standard web TLS relies on X.509 v3 ASN.1 DER structures, specialized PKI standards—such as **IEEE 1609.2** (Wireless Access in Vehicular Environments / V2X Security) and **DANE TLS** (RFC 7671)—introduce alternative micro-certificate paradigms. Evaluating these provides critical insights for `randbotd`:

```
   X.509 v3 (Verbose ASN.1 DER)                 IEEE 1609.2 (Compact COER)
  +-----------------------------+              +---------------------------+
  | Subject DN, Issuer DN       |              | Explicit 8-byte PSIDs     |
  | Long Validity (90-825 days) |   VS         | Micro-TTLs (5 min - 1 hr) |
  | RSA/ECDSA heavy signatures  |              | Implicit Certificate Keys |
  | Heavy Extensions (~2-5 KB)  |              | COER Encoding (< 300 B)   |
  +-----------------------------+              +---------------------------+
```

1. **Compact COER Encoding & Overhead Reduction**: IEEE 1609.2 uses Canonical Octet Encoding Rules (COER) producing certificate payloads under 300 bytes (compared to 2-5 KB for verbose X.509). `randbotd` utilizes compact binary framing over P2P UDP gossip (`NET-02`) to ensure MTU safety while maintaining full X.509 reconstruction capabilities.
2. **Micro-TTLs & Ephemeral Authorization**: IEEE 1609.2 heavily employs short-lived certificates (5 minutes to 1 hour) without revocation lists. In `randbotd`, this matches `ACME-06` (Emergency Default Fallback) and `CA-08` (Custom TTL), where ultra-short validity eliminates the need for expensive P2P CRL propagation during temporary node handoffs.
3. **Explicit Scope / Service Identifiers (PSIDs)**: IEEE 1609.2 uses Provider Service Identifiers (PSIDs) to restrict key permissions. In `randbotd`, this maps to **Name Constraints** (`CA-14`) restricting intermediate CAs to specific TLDs (`.hns`, `.onion`, `.i2p`).

---

### 3.0 Unix Domain Socket IPC Administration & Local Node Control

In a systemd managed installation (`StateDirectory=randbotd`), `randbotd` enforces strict state directory isolation (`/var/lib/randbotd` mode `0750`). Direct daemon administration commands over the Unix domain socket (`/var/lib/randbotd/randbotd.sock`) require administrative privileges using `sudo socat`:

```bash
# Publish Root CA via daemon Unix Domain Socket (sudo socat)
echo '{"PublishCa":{"common_name":"The Random Consortium Root CA","organization":"The Random Consortium","organizational_unit":"PKI Operations","locality":"Valencia","state_or_province":"Valencia","country":"ES","email":"ca@therandomconsortium.org","is_intermediate":false,"path_len_constraint":null}}' | sudo socat - UNIX-CONNECT:/var/lib/randbotd/randbotd.sock
```

> **Security Note**: Direct IPC socket access enforces strict system administrative authorization (`sudo` or `randbotd` user group membership), protecting private keys (`node_key.enc`) and the transactional event log database.

---

## 3. CA Entity Data Model & Operational Architecture

A Certificate Authority in `randbotd` is NOT merely a static cryptographic keypair. It is a **sovereign P2P network entity** with an identity, custodian governance model, multi-tier offer catalog, operational risk boundaries, consensus state, and anti-entropy event log integration.

```
+-----------------------------------------------------------------------------------+
|                                 CA Entity Data Model                              |
+-----------------------------------------------------------------------------------+
| 1. Cryptographic Identity & Custodian                                             |
|    - ca_id: Hash(CA Root PubKey)                                                  |
|    - custodian_type: SingleNode | DistributedSwarm (FROST m-of-n)    [CA-11] *NEW* |
|    - active_custodian_nodes: Vec<NodePubKey>                                      |
+-----------------------------------------------------------------------------------+
| 2. Multi-Tier Offer Catalog                                                       |
|    - catalog_id: Hash(CAPublishOfferCatalog)                         [CA-12] *NEW* |
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

### 3.1 Custodian Identity & Multi-Node Distributed Architecture

A CA is originally registered by a **Custodian**—the initial node operator who emits the `CAPublishDeclaration` event into the P2P log (`NET-04`/`NET-05`). However, to prevent single points of failure, node downtime, or key compromise, `randbotd` supports a two-phase custodian architecture:

#### Phase 1: Single Node Custodian (Initial Registration)
- The CA identity (`CA_ID`) is derived from the SHA-256 hash of the CA's root public key.
- The single creating node signs all CA management declarations (`CAPublishOfferCatalog`, domain purges `CA-07`, key rotations `CA-09`).
- Signing certs is executed directly by the node's local key store.

#### Phase 2: Distributed Custodian Swarm Model (Proposed `CA-11`)
To distribute operational load, prevent server downtime, and protect high-reputation CAs against single-node key theft, `randbotd` establishes the **Distributed Custodian Swarm Engine**:
1. **Threshold Cryptography (FROST / $m$-of-$n$ Schnorr/Ed25519 / ECDSA DKG)**:
   - A CA identity key is generated collectively via **Distributed Key Generation (DKG)** across $n$ custodian nodes without ever assembling the full secret key on a single machine.
   - Any $m$ out of $n$ custodian nodes must collaborate to emit a valid X.509 certificate signature or sign a CA state update.
2. **Parallel ACME Load-Sharing Protocol**:
   - Domain certificate issuance requests (`GetCert`) arriving at the CA's public endpoint can be load-balanced across all active custodian swarm nodes (`active_custodian_nodes`).
   - Domain proof validation (`CA-03`) is executed in parallel by custodian nodes. Once verified, nodes generate threshold partial signatures (`PartialSignatureShare`), which are aggregated into the final valid certificate.

#### 📅 Two-Stage Execution Timeline for `CA-11`:
- **Stage 1 (CA Module Phase 3 / Global Phase 3)**: **Non-Monetary Infrastructure Swarms (0 Fees)**. `CA-11` launches early as a pure P2P load-distribution and high-availability mechanism. Worker nodes join custodian swarms to share validation work and signing duties without monetary compensation (0-cost custodian clusters).
- **Stage 2 (Global Phase 9 - Monero Market Integration)**: **Monetized Swarms & Pay-As-You-Work Revenue-Share**. When the Monero Decentralized Market (`PAY-01` to `PAY-06`) arrives in Global Phase 9, `CA-11` activates work-share fee splits ($P_{\text{worker}}$ under `PAY-03`) and shared purge refund liabilities (`PAY-06`).

#### 4-Step Escrow-Less Custodian Delegation State Machine & Revenue-Share Mechanics (`CA-11`)

To eliminate the moral hazard and rug-pull vector of upfront custodian fees (where a lazy or fraudulent worker node takes an upfront payment and then goes offline or refuses to issue certs), `randbotd` enforces a **Pay-As-You-Work Revenue-Share Settlement Protocol**.

Onboarding a worker node into a CA custodian swarm carries **zero upfront fees**. Instead, worker nodes are compensated dynamically through a **work-share fee percentage ($P_{\text{worker}}$)** per certificate issued. When a domain pays an ACME fee under `PAY-03`, the Monero payment `tx_key` proves on-chain fee distribution directly to the $m$ active co-signing worker nodes that generated threshold partial signatures (`PartialSignatureShare`) for that specific certificate emission.

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

1. **Step 1: Worker Node Emits `CustodianContract` (Work-Share Terms)**:
   - Candidate worker node publishes a signed `CustodianContract` payload into the P2P event log (`NET-05`).
   - Specifies operational parameters: target `CA_ID`, supported algorithms, max allowed TTL, capability backends, max issuance capacity, and requested **Work-Share Fee Percentage $P_{\text{worker}}$** (e.g. 15% of certificate fee per co-signed issuance).
2. **Step 2: CA Emits `CustodianDelegationRequest` (CA Accord)**:
   - Primary CA node emits a signed `CustodianDelegationRequest` targeting the worker node (`WorkerNodePubKey`), according to the terms and work-share percentage $P_{\text{worker}}$.
3. **Step 3: Worker Node Emits `CACapabilitiesProof` (Dummy Cert Build & Liveness Commitment)**:
   - Worker node emits a signed `CACapabilitiesProof` containing a **dummy/test certificate build** signed using the worker's key under accord parameters.
   - **Game Theory & Capability Verification**: Proves active X.509 certificate building engines, crypto libraries, and active capability backends online *before* swarm admission.
4. **Step 4: CA Emits `SwarmActivationConfirmation` (Final Activation)**:
   - CA emits a signed `SwarmActivationConfirmation` admitting the worker node into the active signing quorum.
   - **Network-Wide Validation**: P2P nodes validate all 4 steps (`CustodianContract` $\rightarrow$ `CustodianDelegationRequest` $\rightarrow$ `CACapabilitiesProof` $\rightarrow$ `SwarmActivationConfirmation`).
5. **Trustless Pay-As-You-Work Settlement (`PAY-03` Integration)**:
   - When a domain owner pays for a certificate (e.g. 0.01 XMR), the Monero transaction splits payment: $(100\% - \sum P_{\text{worker}})$ to the CA Treasury, and $P_{\text{worker}}$ directly to each of the $m$ active co-signing custodian nodes.
   - **Game Theory Security Guarantees**:
     - **Lazy Worker Immunity**: Offline or non-performing workers earn 0 XMR.
     - **Risk-Free Revocation**: If a CA revokes a worker node (`CustodianRevocation`) or a contract expires (`DelegationTTL`), **0 CA capital is lost**, because no upfront payment was ever made!
     - **Alignment of Incentives**: Workers are incentivized to maintain high uptime and low latency to participate in co-signing quorums and earn work-share fees.

> [!TIP]
> **Trustless Resolution: The Domain Purge Bounty Protocol (`DomainPurgeBounty`)**:
> To eliminate the trust requirement and liquidity bottleneck of shared purge refund liabilities, `randbotd` establishes the **Domain Purge Bounty Protocol**:
> 1. **Bounty Emission**: If a CA (or custodian swarm) needs to purge a domain (`CA-07` / `PAY-06`) but faces a non-paying custodian node or lacks immediate liquidity, the CA emits a signed P2P `DomainPurgeBounty` specifying the required prorated refund amount and an **agreed yield interest rate ($\Delta r$)**.
> 2. **Direct Domain Owner Fulfillment**: Any market participant (bounty hunter) funds the bounty by sending the prorated refund **directly to the domain owner's address** (proven on-chain via Monero `tx_key` under `BountyFulfillmentProof`). The CA receives 0 XMR directly.
> 3. **Elimination of CA Exit-Scams / Moral Hazard**: Because funds bypass the CA entirely and go straight to the domain owner, a rogue CA has **zero financial incentive to fake bounties or exit-scam**. The CA gains no capital from bounty fulfillment and must continue operating and issuing certificates to resume earning net revenue after settling the repayment queue.
> 4. **Priority Fee Repayment Queue**: Once funded, the domain purge is executed immediately. Next ACME certificate fees earned by that CA under `PAY-03` are automatically routed to **repay the Bounty Hunter first** (Principal + Interest) before net revenue flows to the CA Treasury or custodian workers.
> 5. **Game-Theoretic Risk Assessment**: Bounty hunters make **informed financial decisions** prior to funding by evaluating the CA's historical issuance volume, WoT consensus reputation, and active domain portfolio.

---

### 3.2 Economic Model: Single Offer vs. Multi-Tier Certificate Offer Catalog

#### Architectural Analysis: Single Offer vs. Catalog
A single static offer model (where a CA advertises one fixed price, key type, and TTL) suffers from major market inefficiencies:
- If a CA charges 0.01 XMR, it completely excludes free/zero-cost domain owners (`--free-only`).
- If a CA offers only free issuance, it cannot monetize premium infrastructure (such as 365-day TTLs, multi-domain SAN wildcards, or high-availability guarantee SLAs).

Therefore, `randbotd` enforces a **Multi-Tier Certificate Offer Catalog Model** (Proposed `CA-12`). A CA publishes a single signed `CAPublishOfferCatalog` payload containing an array of structured **Certificate Profiles** (`CertificateProfile`).

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
|   - Max TTL: 90 Days                                                               |
|   - SAN Limit: 1 Single Domain (No Wildcards)                                     |
+------------------------------------------------------------------------------------+
| Profile 1: "Multi-Domain SAN & Wildcard Tier"                                     |
|   - Price: 0.0050 XMR                                                              |
|   - Supported Proofs: DNS TXT, Handshake HNS, Tor ALPN, I2P LeaseSet               |
|   - Allowed Keys: RSA-4096, ECDSA P-384, Ed25519                                  |
|   - Max TTL: 180 Days                                                              |
|   - SAN Limit: Up to 100 SAN Domains (Supports Wildcard *.domain.hns)             |
+------------------------------------------------------------------------------------+
| Profile 2: "Long-TTL Enterprise Tier"                                             |
|   - Price: 0.0200 XMR                                                              |
|   - Supported Proofs: All Multi-Network Backends                                   |
|   - Allowed Keys: All Algorithms (Including Post-Quantum)                         |
|   - Max TTL: 365 Days                                                              |
|   - SAN Limit: Unlimited + Custom OID Enclosure + Priority P2P Issuance           |
+------------------------------------------------------------------------------------+
```

#### Client Matching against the Offer Catalog
During certificate allocation (`GetCert` / `ACME-03`), the client matching engine evaluates available CAs and their catalog profiles:
1. **`--free-only` Flag (`PAY-05`)**: Filters the catalog strictly for Profile entries where `price == 0`.
2. **`account_price_ceiling` (`PAY-04`)**: Filters out any Profile entries exceeding the domain owner's configured budget.
3. **Do-Not-Match (`--dnm`) Exclusions (`ACME-08`)**: Bypasses excluded CAs. If no free-tier candidates remain in the domain's confidence band, the client is prompted to raise their price ceiling to access commercial catalog profiles, driving organic cypherpunk market economics.

---

### 3.3 Operational Parameters & Risk Boundaries

Apart from certificate fields and pricing, a CA entity defines strict operational configuration parameters:

1. **CA Operator Risk Floor Threshold (`ACME-05`) — Downward-Only Risk Amplification**:
   - **Mechanism & Boundary Rules**: A CA operator can set a custom `risk_floor` acceptance threshold (e.g. `risk_floor = 35.0%`). However, this threshold **ONLY permits downward risk expansion below the CA's dynamic lower confidence bound ($50\% - \Delta_{\text{CA}}$)** to voluntarily host lower-reputation or dissident domains.
   - **Anti-Domain-Fishing Rule (Fraud Prevention)**: A CA is **strictly prohibited from raising its risk floor above its natural lower bound to cherry-pick high-reputation domains**. If a CA attempts to set a floor of e.g. 80.0% to exclude lower-reputation domains within its matching confidence band, the fair-band matching engine rejects the configuration. Allowing upward restriction would constitute "domain-fishing fraud"—enabling CAs to artificially boost their aggregate reputation by taking only safe domains while avoiding the dynamic risk matching prescribed by Web-of-Trust consensus.
2. **Multi-Network Proof Backends (`CA-03`)**:
   - Bitmask declaring which validation backends the CA node currently operates (`DNS_TXT`, `HANDSHAKE_HNS`, `TOR_ALPN`, `I2P_LEASESET`, `HTTP_NONCE`).
   - Advertising support for a network protocol without an active proxy/daemon running locally causes startup validation failure.
3. **Issuance Epoch Capacity & Throttling**:
   - Max certificates emitted per hour/epoch to prevent resource exhaustion, DDoS, or key overuse.
4. **Emergency Short-TTL Fallback Mode (`ACME-06`)**:
   - Ability to emit short-lived (e.g. 24-hour) emergency certificates if the main signing pipeline or custodian node is undergoing maintenance.

---

### 3.4 Consensus State, Reputation & Anti-Entropy Event Log Binding

Every CA entity is permanently tracked in the `randbotd` P2P event log (`NET-04`/`NET-05`). Its state comprises:

1. **Baseline 50% Initializer (`ACME-02`)**:
   - Newly published CAs start at a neutral 50% score with 0 votes and a maximum confidence window ($\Delta_{\text{CA}} = \pm 50\%$).
2. **Logarithmic Confidence Window ($\pm \Delta_{\text{CA}}$) Engine (`ACME-04`)**:
   - Evaluates the ensemble of all domains issued by the CA, taking the 75th percentile (P75) domain vote count to compute the CA's dynamic window:
     $$\Delta_{\text{CA}} = \pm 50\% \times f\left(\frac{\text{P75}(\{N_{\text{votes}}(\text{domain}_i)\})}{N_{\text{active\_nodes}}}\right)$$
3. **Distrust Strike Accumulator (`REP-09`)**:
   - Stores all permanent, non-decaying market distrust strikes emitted by domain owners executing early renewals.
4. **Key Rotation & Remediation Ledger (`CA-09`)**:
   - Cryptographic record of `KeyRotationProof` payloads published to revoke compromised key material and reset standing strikes.
5. **Node-Bound Anti-Entropy Sequence Binding (`NET-05`)**:
   - Every state change emitted by a CA (catalog update, domain purge, key rotation) is bound to a monotonic sequence integer and linked hash (`seq`, `prev_hash`), ensuring deterministic, tamper-proof synchronization across all P2P nodes.

---

### 3.5 Local Node Verification Sovereignty & Anti-Solipsism Game Theory

In traditional web PKI, Certificate Authorities act as central oracles: if a CA publishes a revocation list (CRL/OCSP), browser clients obey blindly. In `randbotd`, **no CA declaration, certificate emission, extension payload, or revocation assertion is trusted at face value**. Every participant operates under absolute **Local Node Verification Sovereignty**:

1. **Zero Central Trust / Local Verification Pipeline**:
   - Every node in the `randbotd` P2P network independently executes verification for every payload broadcasted over gossip.
   - A CA cannot simply emit a certificate, extension (e.g. `CA-03` domain proof, `PAY-03` payment proof, `CA-10` critical WoT OID, `CA-14` name constraints), or revocation (`CA-07` purge) onto the net and expect nodes to accept it blindly.
   - Domain owners cannot "hot-modify" certificates; any certificate modification requires a new issuance sequence signed by the CA and validated against network consensus by every listening peer.

2. **Verification of Emitted Extensions & Cryptographic Proofs**:
   - **Payment Proofs (`PAY-03`)**: Recipient nodes verify the Monero `tx_key` directly against the Monero blockchain to confirm fee settlement before admitting the certificate transaction into local Web-of-Trust state.
   - **Domain Ownership Proofs (`CA-03`)**: Recipient nodes re-verify the cryptographic proof signature (DNS TXT hash, Handshake record signature, Tor ALPN proof, or HTTP Nonce signature) against the domain owner's P2P key identity.
   - **WoT Extension & Name Constraint Integrity (`CA-10`/`CA-14`)**: Recipient nodes verify ASN.1 encoding structures and OID provenance.

3. **Lying CAs & Solipsistic Rejection**:
   - If a CA lies (e.g. emits an unauthorized domain purge without valid PoW/strike evidence, or emits a cert with faked payment/proof extensions):
     - **The CA's lie is ignored by every local node.** The revocation or fake cert fails local cryptographic validation and will **NOT** take effect in the final daemon state of end users.
     - The lying CA exists in a **solipsistic parallel universe**—believing it emitted an action, while the rest of the P2P swarm rejects the log event and applies heuristic cluster penalties (`REP-07`) against the CA's voter weight.
   - Network consensus is realized strictly when independent local nodes evaluate the cryptographic evidence and declare: *"We trust this emission."*

---

## 4. Comprehensive Standards Reference Matrix

The design of `randbotd` certificate structures and CA entities strictly adheres to and extends established global cryptographic and internet engineering standards:

| Standard Identifier | Title / Description | Scope in `randbotd` | Relevant Feature IDs |
| :--- | :--- | :--- | :--- |
| **RFC 5280** | Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile | Core X.509 v3 structure, standard extensions (Basic Constraints, SAN, Key Usage, EKU, AKI/SKI, Name Constraints, CDP, AIA), critical OID processing rules. | `CA-01`, `CA-05`, `CA-10`, `CA-13`, `CA-14`, `CA-15` |
| **RFC 8446** | The Transport Layer Security (TLS) Protocol Version 1.3 | Transport layer handshake framing, certificate message structure, TLS ALPN extension validation. | `CA-03`, `ECO-01`, `OUT-01` |
| **RFC 8555** | Automatic Certificate Management Environment (ACME) | Standardized ACME v2 endpoints (`/acme/directory`, `/acme/new-order`, `/acme/finalize`), domain validation challenges. | `ACME-01` through `ACME-08` |
| **RFC 6962** | Certificate Transparency (CT) | Audit proof structures and Signed Certificate Timestamps (SCTs). Replaced/augmented in `randbotd` by P2P Merkle event log sequence proofs. | `NET-05`, `CA-04` |
| **RFC 8032** | Edwards-Curve Digital Signature Algorithm (Ed25519) | High-speed, secure Ed25519 keypair generation and certificate signature generation/verification. | `NET-01`, `CA-02`, `CA-05` |
| **RFC 5480** | Elliptic Curve Cryptography Subject Public Key Information | ASN.1 encoding structures for ECDSA public keys and curves (secp256r1, secp384r1, secp521r1). | `CA-02`, `CA-05` |
| **RFC 7671** | DANE TLS Authentication | DNS-based Authentication of Named Entities. Concepts applied to Handshake `.hns` domain control proofs. | `CA-03` |
| **ITU-T X.509 / ISO/IEC 9594-8** | Information technology - Open Systems Interconnection - Public-key and attribute certificate frameworks | Foundational directory and attribute certificate specifications. | `CA-01`, `CA-05` |
| **ITU-T X.667 / ISO/IEC 9834-8** | Generation and registration of Universally Unique Identifiers (UUIDs) and use as ASN.1 OIDs | Derivation of the critical custom WoT OID `2.25.332006307751889903095271628869501346770.1.1` from root UUID `f9c616c7-8e4d-4f84-a32e-596b5ada63d2`. | `CA-10` |
| **IEEE 1609.2** | Standard for Wireless Access in Vehicular Environments -- Security Services for Applications and Management | Micro-certificate TTL design, compact COER wire encodings, explicit permission/PSID boundaries. | `CA-08`, `CA-14`, `ACME-06` |
| **CA/Browser Forum BR v2.0+** | Baseline Requirements for the Issuance and Management of Publicly-Trusted Certificates | 64-160 bit serial number entropy rules, maximum validity periods, domain validation requirements. | `CA-03`, `CA-08`, `CA-13` |
| **NIST SP 800-57 Part 1** | Recommendation for Key Management | Cryptographic key lifetime recommendations, algorithm transition guidelines, random number generator standards. | `CA-02`, `CA-09`, `CA-13` |

---

## 5. Newly Proposed Functionalities for `FUNCTIONALITIES.md`

To address the gaps identified during this comprehensive investigation, the following 5 feature modules are formally proposed for inclusion in `FUNCTIONALITIES.md` under **Section 2: Root & Intermediate CA Engine**:

```markdown
| Feature ID | Module Name | Description | Status |
| :--- | :--- | :--- | :---: |
| `CA-11` | **Distributed Custodian Swarm & Threshold Key Delegation Engine** | Enables CAs to distribute operational load and key signing across $n$ decentralized nodes using threshold cryptography (FROST / $m$-of-$n$ Schnorr/Ed25519 DKG). Includes `CustodianDelegationProof` payloads for delegating short-lived operational issuance rights to worker nodes while protecting root key material. | ⚪ |
| `CA-12` | **Multi-Tier CA Certificate Offer Catalog & Profile Engine** | Replaces single static pricing with a structured Offer Catalog (`CAPublishOfferCatalog`). Allows CAs to publish multiple `CertificateProfile` options (e.g. Profile 0: Free Standard short-TTL, Profile 1: Multi-SAN/Wildcard, Profile 2: Long-TTL Enterprise) seamlessly integrated with client `--free-only` and `account_price_ceiling` filters. | ⚪ |
| `CA-13` | **Cryptographic Certificate Serial Entropy Engine** | Standard-compliant generator (RFC 5280 / CABF BR §7.1.4.2.1) injecting 64-160 bits of CSPRNG entropy into X.509 certificate serial numbers (`CertificateSerialNumber`) to immunize certificate issuance against hash collision and serial prediction attacks. | 🔴 |
| `CA-14` | **Subtree Name Constraints Engine (`permittedSubtrees`/`excludedSubtrees`)** | Standard-compliant implementation of X.509 v3 Name Constraints extension (RFC 5280 §4.2.1.10) marked `critical = TRUE`. Allows Intermediate CAs to be cryptographically restricted to specific domain namespaces (e.g., strictly `.hns`, `.onion`, `.i2p`, or specific domain subtrees). | 🔴 |
| `CA-15` | **P2P Authority Information Access (AIA) & P2P OCSP Engine** | Extends RFC 5280 AIA extension (`1.3.6.1.5.5.7.1.1`) with `randbotd://` P2P swarm URIs for fetching parent CA cert chains (`caIssuers`) and checking real-time P2P revocation status (`id-ad-ocsp`) directly over gossip without central Web server dependencies. | 🔴 |
```

---
