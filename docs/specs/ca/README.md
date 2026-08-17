# 📜 `randbotd` PKI & Certificate Specifications
### *Master Architecture, Standard Field Mappings, CA Custodian Governance & P2P Web-of-Trust*

This directory contains the authoritative specification suite for `randbotd`'s decentralized Public Key Infrastructure (PKI), Certificate Authority (CA) entities, and custom Web-of-Trust (WoT) X.509 extensions.

---

## 📑 Specification Suite Index

| Specification Part | Document File | Core Coverage & Key Standard Modules |
| :--- | :--- | :--- |
| **Part 1: Certificate Definition** | [`01_certificate_definition.md`](file:///home/mreugenej7/git/randbotd/docs/specs/ca/01_certificate_definition.md) | Standard X.509 v3 header fields (RFC 5280 §4.1), standard extensions (§4.2), custom WoT OID extensions (`CA-10`), domain proofs (`CA-03`), and IEEE 1609.2 comparative attributes. |
| **Part 2: CA Entities & Operational Model** | [`02_ca_entities_and_operational_model.md`](file:///home/mreugenej7/git/randbotd/docs/specs/ca/02_ca_entities_and_operational_model.md) | CA data model, custodian identity, distributed swarm delegation (`CA-11`), multi-tier offer catalog (`CA-12`), downward-only risk floors (`ACME-05`), anti-solipsism, and local node verification sovereignty. |
| **Part 3: Standards & Implementation Notes** | [`03_standards_and_ca12_design.md`](file:///home/mreugenej7/git/randbotd/docs/specs/ca/03_standards_and_ca12_design.md) | International standards reference matrix (RFC 5280, RFC 8446, RFC 8555, ITU-T X.667), proposed feature additions, and pre-implementation architectural commitments for `CA-12` catalog subtable separation. |

---

## 🏗️ Architecture Overview

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
