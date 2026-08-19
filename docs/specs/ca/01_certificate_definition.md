# 📜 `randbotd` Certificate Specification & Field Mapping
### *Part 1: Complete X.509 v3 Header Fields, Standard Extensions, Custom WoT OIDs & IEEE 1609.2 Attributes*

---

## 1. Executive Summary & Architectural Context

In traditional Public Key Infrastructure (PKI), Certificate Authorities (CAs) act as centralized, opaque issuers whose certificate profiles and internal metadata are tightly dictated by browser vendor cartels (CA/Browser Forum Baseline Requirements). In `randbotd`, Public Key Infrastructure is reimagined as a **decentralized, peer-evaluated Web-of-Trust (WoT) consensus engine**. 

To deliver complete cryptographic sovereignty, multi-network domain equality (supporting clearnet, Handshake `.hns`, Tor `.onion`, and I2P `.i2p`), and cypherpunk market dynamics, `randbotd` requires a precise, exhaustive specification of:
1. **Configurable Certificate Parameters**: Every standard field, X.509 extension, custom OID, and handshake attribute present in modern TLS certificates.
2. **CA Entity Properties**: All data structures, operational boundaries, custodian identities, load-sharing mechanisms, and pricing offer models that define a CA node within the P2P swarm.
3. **International Standards Alignment**: Concrete cross-references to official IETF RFCs, ITU-T recommendations, IEEE standards, and CA/Browser Forum guidelines.

This document establishes the authoritative blueprint for `CA-01` (**Custom Subject Metadata Engine**), `CA-10` (**Critical Custom X.509 OID Extension Engine**), and their integration with the broader `randbotd` ecosystem.

---

## 2. Complete TLS Certificate Field Investigation & Mapping Matrix

An X.509 v3 certificate (RFC 5280) consists of a signed payload (`TBSCertificate`), a signature algorithm identifier, and a digital signature emitted by the issuing CA key. Below is an exhaustive breakdown of all configurable attributes, their standards references, and their explicit mapping to `randbotd` feature modules.

```
       +-------------------------------------------------------+
       |                  X.509 v3 Certificate                 |
       +-------------------------------------------------------+
       | TBSCertificate:                                       |
       |   - Version (v3)                        [CA-05]       |
       |   - Serial Number (64-160 bit Entropy)  [CA-13]       |
       |   - Signature Algorithm OID             [CA-02]       |
       |   - Issuer DN (C, O, OU, CN...)         [CA-01]       |
       |   - Validity Period (notBefore/notAfter)[CA-08]       |
       |   - Subject DN (C, O, OU, CN...)        [CA-01]       |
       |   - SubjectPublicKeyInfo (RSA/EC/Ed)    [CA-02]       |
       |   - Extensions:                                       |
       |       * Basic Constraints               [CA-01/05]    |
       |       * Key Usage & EKU                 [CA-05]       |
       |       * Subject Alternative Name (SAN)  [CA-03/05]    |
       |       * Name Constraints (Subtrees)     [CA-14]       |
       |       * Authority/Subject Key ID        [CA-05]       |
       |       * CRL Distribution Points (CDP)   [CA-04/07]    |
       |       * Authority Info Access (AIA/OCSP)[CA-15]       |
       |       * Critical WoT OID (2.25.332...)  [CA-10]       |
       |       * Domain Proof Binding Extension  [CA-03]       |
       +-------------------------------------------------------+
       | Signature Algorithm OID                 [CA-02]       |
       | CA Digital Signature (RSA/ECDSA/Ed25519)[CA-02/05]   |
       +-------------------------------------------------------+
```

---

### 2.1 Standard X.509 v3 Certificate Header Fields (RFC 5280 §4.1)

| Field Name | ASN.1 / Data Structure | Configurable Parameters & Options | Standards Reference | Feature ID | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **Version** | `INTEGER { v1(0), v2(1), v3(2) }` | Standardized to `v3` (2). Mandatory for extension support. | RFC 5280 §4.1.2.1 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Serial Number** | `CertificateSerialNumber ::= INTEGER` | Cryptographically random integer (minimum 64 bits, up to 160 bits of entropy). Prevents collision and certificate forgery attacks. | RFC 5280 §4.1.2.2, CABF BR §7.1.4.2.1 | `CA-13` (Cryptographic Serial Entropy Engine) | 🟢 |
| **Signature Algorithm Identifier** | `AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }` | OID and parameters for the issuing CA signature. Supported: RSA-PSS/PKCS#1 v1.5, ECDSA (secp384r1), Ed25519, and Post-Quantum (ML-DSA-44). | RFC 5280 §4.1.2.3, RFC 8032, RFC 5480 | `CA-02` (Cryptographic Agility Suite) | 🟢 |
| **Issuer Distinguished Name (Issuer DN)** | `Name ::= CHOICE { RDNSequence }` | Distinguished Name of the issuing CA. Configurable fields: Country (`C`), State/Province (`ST`), Locality (`L`), Organization (`O`), Organizational Unit (`OU`), Common Name (`CN`), Email. | RFC 5280 §4.1.2.4, ITU-T X.500 | `CA-01` (Custom Subject Metadata Engine) | 🟢 |
| **Validity Period** | `Validity ::= SEQUENCE { notBefore Time, notAfter Time }` | Time window during which the certificate is cryptographically valid. Expressed in `UTCTime` or `GeneralizedTime`. Supports custom short/long TTLs (1 day to 825 days) and ephemeral micro-TTLs. | RFC 5280 §4.1.2.5, CABF BR §6.3.2 | `CA-08` (Configurable Cert Parameters / Custom TTL) | 🟢 |
| **Subject Distinguished Name (Subject DN)** | `Name ::= CHOICE { RDNSequence }` | Distinguished Name of the certificate owner. Configurable fields: Country (`C`), Locality (`L`), Organization (`O`), Organizational Unit (`OU`), Common Name (`CN`), Email. | RFC 5280 §4.1.2.6, ITU-T X.500 | `CA-01` (Custom Subject Metadata Engine) | 🟢 |
| **Subject Public Key Info** | `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }` | Encapsulates the public key of the subject node/domain. Configurable key algorithms (RSA 4096, ECDSA P-384, Ed25519, ML-DSA-44). | RFC 5280 §4.1.2.7, RFC 5480, RFC 8032 | `CA-02` (Cryptographic Agility Suite), `CA-05` (X.509 Builder) | 🟢 / 🔴 |
| **Issuer / Subject Unique ID** | `UniqueIdentifier ::= BIT STRING` | Optional X.509 v2/v3 fields used to resolve name reuse. Deprecated in modern PKI but supported in builder parsing. | RFC 5280 §4.1.2.8 | `CA-05` (X.509 Certificate Builder) | 🔴 |

---

### 2.2 Standard X.509 v3 Extensions (RFC 5280 §4.2)

| Extension Name | Extension OID | Criticality | Configurable Parameters & Purpose | Standards Reference | Feature ID | Status |
| :--- | :--- | :---: | :--- | :--- | :--- | :---: |
| **Basic Constraints** | `2.5.29.19` | `TRUE` (for CA) / `FALSE` (Leaf) | `cA` (BOOLEAN: `TRUE` for Root/Intermediate CAs, `FALSE` for leaf certs), `pathLenConstraint` (INTEGER: max depth of downstream chains). | RFC 5280 §4.2.1.9 | `CA-01` (Metadata Engine), `CA-05` (X.509 Builder) | 🟢 / 🔴 |
| **Key Usage** | `2.5.29.15` | `TRUE` | Bitmask defining cryptographic key purpose: `digitalSignature`, `nonRepudiation`, `keyEncipherment`, `keyCertSign` (CA signing), `cRLSign`. | RFC 5280 §4.2.1.3 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Extended Key Usage (EKU)** | `2.5.29.37` | `TRUE` or `FALSE` | Key purpose OIDs: `serverAuth` (`1.3.6.1.5.5.7.3.1`), `clientAuth` (`1.3.6.1.5.5.7.3.2`), `codeSigning`, `emailProtection`. | RFC 5280 §4.2.1.12 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Subject Alternative Name (SAN)** | `2.5.29.17` | `FALSE` (or `TRUE` if DN empty) | `GeneralNames` sequence binding identities to cert: `dNSName` (clearnet, Handshake `.hns`, wildcards `*.example.hns`), `iPAddress`, `uniformResourceIdentifier` (Tor `.onion`, I2P `.i2p`). | RFC 5280 §4.2.1.6, RFC 8555 §7.4 | `CA-03` (Multi-Network Domain Proofs), `CA-05` (X.509 Builder) | 🟢 / 🔴 |
| **Name Constraints** | `2.5.29.30` | `TRUE` | Restricted subtree scope for Intermediate CAs: `permittedSubtrees` and `excludedSubtrees` (e.g. limiting an Intermediate CA strictly to `.hns` or `.onion` domains). | RFC 5280 §4.2.1.10 | `CA-14` (Subtree Name Constraints Engine) | 🔴 |
| **Certificate Policies** | `2.5.29.32` | `FALSE` | Sequence of policy OIDs, Certification Practice Statement (CPS) URIs, and User Notices describing CA issuance policies and legal/operational terms. | RFC 5280 §4.2.1.4 | `CA-05` (X.509 Builder), `PAY-01` (Service Fee Publisher) | 🔴 |
| **Authority Key Identifier (AKI)** | `2.5.29.35` | `FALSE` | Identifies the public key corresponding to the private key used to sign the cert. SHA-256 key identifier hash or issuer name + serial number. | RFC 5280 §4.2.1.1 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Subject Key Identifier (SKI)** | `2.5.29.14` | `FALSE` | SHA-256 hash of the subject public key. Essential for constructing certificate validation chains. | RFC 5280 §4.2.1.2 | `CA-05` (X.509 Certificate Builder) | 🔴 |
| **Authority Info Access (AIA)** | `1.3.6.1.5.5.7.1.1` | `FALSE` | Access descriptors: `id-ad-ocsp` and `id-ad-caIssuers`. In `randbotd`, augmented by P2P swarm queries. | RFC 5280 §4.2.2.1, RFC 6960 | `CA-15` (P2P AIA & OCSP Extension Engine) | 🔴 |

---

### 2.3 `randbotd` Custom & Web-of-Trust Extensions

| Extension Name | Extension OID | Criticality | Purpose & Cryptographic Behavior | Standards Reference | Feature ID | Status |
| :--- | :--- | :---: | :--- | :--- | :--- | :---: |
| **Critical WoT Validation Extension** | `2.25.332006307751889903095271628869501346770.1.1` | `TRUE` | Derived from ITU-T X.667 UUID `f9c616c7-8e4d-4f84-a32e-596b5ada63d2`. Enforces voluntary opt-in (un-augmented legacy browsers reject the cert), prevents free-riding, and neutralizes stolen/unpaid certificates outside P2P consensus. | ITU-T X.667 / RFC 5280 §4.2 | `CA-10` (WoT Critical OID Extension) | 🟢 |
| **Domain Proof Binding Extension** | Custom `randbotd` OID (`2.25.332006307751889903095271628869501346770.1.2`) | `FALSE` | Embeds the cryptographic proof signature (DNS TXT record hash, Handshake record signature, Tor ALPN proof, or HTTP Nonce signature) validating domain control at issuance time. | RFC 8555, `randbotd` Spec | `CA-03` (Multi-Network Domain Proofs) | 🟢 |
| **Out-of-Net Classification Tag** | Custom `randbotd` OID (`2.25.332006307751889903095271628869501346770.1.3`) | `FALSE` | Mandatory tag isolating self-signed, Caddy internal, or legacy ICANN certificates ingested into the local node trust store from native peer-voted `randbotd` CAs. | `randbotd` Manifesto §3.4 | `OUT-03` (`out-of-net` Cryptographic Marking) | 🔴 |
| **Monero Settlement Binding (`TxKeyProof`)** | Custom `randbotd` OID (`2.25.332006307751889903095271628869501346770.1.4`) | `FALSE` | Binds the certificate digest to the Monero `tx_key` and contract constitution hash, enabling P2P nodes to verify fee settlement on-chain without third-party escrow. | `randbotd` Manifesto §3.5 | `PAY-03` (3-Step Escrow-less Settlement) | 🔴 |

---

### 2.4 IEEE 1609.2 & Specialized PKI Certificate Attributes

While standard web TLS relies on X.509 v3 ASN.1 DER structures, specialized PKI standards—such as **IEEE 1609.2** (Wireless Access in Vehicular Environments / V2X Security) and **DANE TLS** (RFC 7671)—introduce alternative micro-certificate paradigms:

```
   X.509 v3 (Verbose ASN.1 DER)                 IEEE 1609.2 (Compact COER)
  +-----------------------------+              +---------------------------+
  | Subject DN, Issuer DN       |              | Explicit 8-byte PSIDs     |
  | Long Validity (90-825 days) |   VS         | Micro-TTLs (5 min - 1 hr) |
  | RSA/ECDSA heavy signatures  |              | Implicit Certificate Keys |
  | Heavy Extensions (~2-5 KB)  |              | COER Encoding (< 300 B)   |
  +-----------------------------+              +---------------------------+
```

1. **Compact COER Encoding & Overhead Reduction**: IEEE 1609.2 uses Canonical Octet Encoding Rules (COER) producing certificate payloads under 300 bytes. `randbotd` utilizes compact binary framing over P2P UDP gossip (`NET-02`) to ensure MTU safety while maintaining full X.509 reconstruction capabilities.
2. **Micro-TTLs & Ephemeral Authorization**: IEEE 1609.2 heavily employs short-lived certificates without revocation lists. In `randbotd`, this matches `ACME-06` and `CA-08` (Custom TTL), where ultra-short validity eliminates the need for expensive P2P CRL propagation during temporary handoffs.
3. **Explicit Scope Identifiers (PSIDs)**: In `randbotd`, this maps to **Name Constraints** (`CA-14`) restricting intermediate CAs to specific TLDs (`.hns`, `.onion`, `.i2p`).
