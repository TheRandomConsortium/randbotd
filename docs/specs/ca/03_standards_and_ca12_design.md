# 📜 `randbotd` Standards Reference & CA-12 Design Commitments
### *Part 3: International Standards Alignment, Proposed Feature Sets & CA-12 Subtable Architecture*

---

## 4. Comprehensive Standards Reference Matrix

`randbotd` certificate structures and CA entities strictly adhere to and extend established global cryptographic standards:

| Standard Identifier | Title / Description | Scope in `randbotd` | Relevant Feature IDs |
| :--- | :--- | :--- | :--- |
| **RFC 5280** | Internet X.509 Public Key Infrastructure Certificate and CRL Profile | Core X.509 v3 structure, standard extensions (Basic Constraints, SAN, Key Usage, EKU, AKI/SKI, Name Constraints, CDP, AIA), critical OID processing rules. | `CA-01`, `CA-05`, `CA-10`, `CA-13`, `CA-14`, `CA-15` |
| **RFC 8446** | The Transport Layer Security (TLS) Protocol Version 1.3 | Transport layer handshake framing, certificate message structure, TLS ALPN extension validation. | `CA-03`, `ECO-01`, `OUT-01` |
| **RFC 8555** | Automatic Certificate Management Environment (ACME) | Standardized ACME v2 endpoints (`/acme/directory`, `/acme/new-order`, `/acme/finalize`), domain validation challenges. | `ACME-01` through `ACME-08` |
| **RFC 6962** | Certificate Transparency (CT) | Audit proof structures and Signed Certificate Timestamps (SCTs). Replaced/augmented in `randbotd` by P2P Merkle event log sequence proofs. | `NET-05`, `CA-04` |
| **RFC 8032** | Edwards-Curve Digital Signature Algorithm (Ed25519) | High-speed, secure Ed25519 keypair generation and certificate signature generation/verification. | `NET-01`, `CA-02`, `CA-05` |
| **RFC 5480** | Elliptic Curve Cryptography Subject Public Key Information | ASN.1 encoding structures for ECDSA public keys and curves (secp384r1). | `CA-02`, `CA-05` |
| **RFC 7671** | DANE TLS Authentication | DNS-based Authentication of Named Entities. Concepts applied to Handshake `.hns` domain control proofs. | `CA-03` |
| **ITU-T X.509 / ISO/IEC 9594-8** | Public-key and attribute certificate frameworks | Foundational directory and attribute certificate specifications. | `CA-01`, `CA-05` |
| **ITU-T X.667 / ISO/IEC 9834-8** | Generation of UUIDs and use as ASN.1 OIDs | Derivation of the critical custom WoT OID `2.25.332006307751889903095271628869501346770.1.1` from root UUID `f9c616c7-8e4d-4f84-a32e-596b5ada63d2`. | `CA-10` |
| **IEEE 1609.2** | Wireless Access in Vehicular Environments -- Security Services | Micro-certificate TTL design, compact wire encodings, explicit permission/PSID boundaries. | `CA-08`, `CA-14`, `ACME-06` |
| **CA/Browser Forum BR v2.0+** | Baseline Requirements for Publicly-Trusted Certificates | 64-160 bit serial number entropy rules, maximum validity periods, domain validation requirements. | `CA-03`, `CA-08`, `CA-13` |
| **NIST SP 800-57 Part 1** | Recommendation for Key Management | Cryptographic key lifetime recommendations, algorithm transition guidelines, random number generator standards. | `CA-02`, `CA-09`, `CA-13` |

---

## 5. Proposed CA Feature Modules

```markdown
| Feature ID | Module Name | Description | Status |
| :--- | :--- | :--- | :---: |
| `CA-11` | **Distributed Custodian Swarm & Threshold Key Delegation Engine** | Enables CAs to distribute operational load and key signing across $n$ decentralized nodes using threshold cryptography (FROST / $m$-of-$n$ Schnorr/Ed25519 DKG). | ⚪ |
| `CA-12` | **Multi-Tier CA Certificate Offer Catalog & Profile Engine** | Replaces single static pricing with a structured Offer Catalog (`CAPublishOfferCatalog`). | 🟢 |
| `CA-13` | **Cryptographic Certificate Serial Entropy Engine** | Standard-compliant generator (RFC 5280 / CABF BR §7.1.4.2.1) injecting 64-160 bits of CSPRNG entropy into certificate serial numbers. | 🟢 |
| `CA-14` | **Subtree Name Constraints Engine (`permittedSubtrees`/`excludedSubtrees`)** | Standard-compliant implementation of X.509 v3 Name Constraints extension (RFC 5280 §4.2.1.10) marked `critical = TRUE`. | 🔴 |
| `CA-15` | **P2P Authority Information Access (AIA) & P2P OCSP Engine** | Extends RFC 5280 AIA extension with `randbotd://` P2P swarm URIs for parent chains and real-time P2P revocation status. | 🔴 |
```

---

## 6. CA-12 Design Reflections & Pre-Implementation Commitments

### 6.1 Catalog Storage: Subtable vs. Embedded in `CaDeclaration`

The Offer Catalog (`CAPublishOfferCatalog`) must **not** live inside the main `CaDeclaration` struct.

| Aspect | Embedded in `CaDeclaration` | Separate `CAPublishOfferCatalog` Event |
| :--- | :--- | :--- |
| **P2P message size** | Bloats every CA declaration message by 2–6 KB. Breaches UDP gossip MTU ceiling (< 1400 bytes). | Keeps `CaDeclaration` compact (< 600 B); catalogs fetched on demand. |
| **Update frequency** | Forces re-signing the entire CA identity whenever catalog pricing or profile limits change. | Catalog versioning updates independently without touching root identity. |
| **Indexing** | Requires full deserialization of CA declarations to query price filters. | Dedicated `ca_catalogs` subtable allows instant catalog-only filtering. |

**Decision:** `CaDeclaration` contains a 32-byte pointer `current_catalog_hash: Option<[u8; 32]>`. The full profile catalog is stored in the `ca_catalogs` subtable.

---

### 6.2 Immutable vs. Mutable CA Fields

#### Immutable at Genesis (never changes after `CAPublishDeclaration`)
- `ca_id: [u8; 32]`: Bound to owner node identity public key and root common name.
- `owner_node_pubkey: [u8; 32]`: Authority anchor signing all management events.
- `is_intermediate: bool`: Frozen in root cert Basic Constraints.
- `path_len_constraint: Option<u32>`: Frozen at genesis.
- `created_at: u64`: Genesis timestamp.

#### Mutable via Owner Node Signed P2P Events
- `subject: CaSubjectMetadata`: Display metadata (O, OU, email).
- Operational cert-signing keypairs (`CA-09` rotation).
- `supported_domain_networks`: Advertised capability backends.
- `custodian_nodes: Vec<NodePubKey>`: Swarm membership (`CA-11`).
- `catalog_version` / `CertificateProfile[]`: Catalog updates (`CA-12`).

---

### 6.3 P2P Message Separation

```
P2P Event Type         Approx. Size     Broadcast Frequency
─────────────────────────────────────────────────────────────
CAPublishDeclaration   ~400–600 B       Once at genesis + rare identity updates
CAPublishOfferCatalog  ~1–6 KB          Per pricing/profile update (weekly/monthly)
CertificateIssuance    ~2–5 KB          Per cert issued (staged pull protocol)
KeyRotationProof       ~300–500 B       Per key rotation event (annually)
CACapabilityUpdate     ~150–300 B       On daemon backend config change
```

1. `CAPublishDeclaration` is an identity beacon carrying only `current_catalog_hash`.
2. `CAPublishOfferCatalog` is gossiped independently with its own monotonic sequence.
3. `CertificateIssuance` (`CA-05`) is never bundled into UDP broadcast frames.

---

### 6.4 Per-Profile Signing Key Selection

A CA may use different signing algorithms for different catalog profiles (e.g. Profile 0: Ed25519, Profile 1: ECDSA P-384, Profile 2: ML-DSA-44).
- The `ca_id` remains constant because it is anchored to the owner node key.
- Each `CertificateProfile` carries a `signing_key_id` referencing the operational key fingerprint.
- Verification chain: `cert signature → operational key → catalog profile → owner node signature → ca_id`.
