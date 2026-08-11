# 🗺️ `randbotd` Specification & Functionality Tracker

This document tracks all planned, ongoing, and completed feature modules, architectural primitives, and ecosystem integrations for `randbotd`.

---

## 📊 Feature Status Legend

| Status Icon | Meaning |
| :---: | :--- |
| 🟢 | **Completed & Verified** |
| 🟡 | **In Active Development** |
| 🔴 | **Infrastructure / Planned** |
| ⚪ | **Conceptual / Specification Draft** |

---

## 🏗️ 1. Core Daemon & P2P Network Infrastructure

| Feature ID | Module Name | Description | Status |
| :--- | :--- | :--- | :---: |
| `NET-01` | **Ed25519 Node Identity** | Node keypair generation, cryptographic identity persistence, and handshake framing. | 🟢 |
| `NET-02` | **Multi-Hop P2P Gossip Engine** | Multi-hop gossip protocol (unlike single-hop designs) for resilient, network-wide propagation of votes, CA declarations, and signed address updates (`AddressAnnouncement`). Includes seen-cache deduplication, UPnP port mapping, and phonebook seed resolution (`therandomconsortium.org:43210`). | 🟢 |
| `NET-03` | **Multi-Network Proxy Integration & Declarative Ports** | Declarative TOML configuration file (`randbotd.toml` / `/etc/randbotd/randbotd.toml`) to manage daemon settings (`port`, `seed`, `external_addr`, `state_dir`) and delegate privacy overlay transport (`tor_socks_proxy = "127.0.0.1:9050"`, `i2p_proxy_port = 7656`). Clearnet peers are strictly NOT routed over Tor/I2P exit nodes because exit nodes block non-standard P2P UDP ports. | 🟢 |
| `NET-04` | **Local Embedded Database** | Fast transactional storage (`Database` JSONL event log + `sync_offset.state`) for local CA state, votes, certificates, and persistent anti-entropy state pagination. | 🟢 |
| `NET-05` | **Full History Catch-Up & Anti-Entropy Protocol** | Node-bound monotonic integer + linked hash hybrid event log (`seq`, `prev_hash`). Anti-entropy sync exchanges node-scoped range vectors (`Node_A: [1..N]` with gap lists) via MTU-safe 4-step intersect exchange capped at 8 originators, backed by a recursive binary Merkle subtree drill-down state machine (`MerkleDrillRequest` / `MerkleDrillResponse`) for deep sequence fragmentation. | 🟢 |
| `NET-06` | **Infrastructure / Headless Node Mode (`--mode=headless`)** | Daemon flag & systemd service for non-interactive nodes. Enforces v1.0.0 cryptographic key domain separation (`NodeRole::Headless` vs `NodeRole::Voter`), deriving distinct Ed25519 public keys (`randbotd_v1_identity_domain_headless`). Headless keys are cryptographically prohibited from casting consensus votes, rendering vote-hijacking impossible without changing key identity. | 🟢 |
| `NET-07` | **Do-Not-Use Clearnet Peers Config (`do_not_use_clearnet_peers`)** | Configuration & CLI flag suppressing connections to clearnet IPv4/v6 peers, advertising/using `.onion` or `.i2p` hidden service addresses exclusively. Note: Since default genesis seed (`therandomconsortium.org`) is clearnet, enabling this option requires importing an `.onion` or `.i2p` seed to bootstrap. | 🟢 |
| `NET-08` | **Overlay Peer Discovery & Phonebook Sharing Engine** | P2P address book (`Phonebook`) 8-peer random sampling exchange protocol (`GetPeersRequest`/`GetPeersResponse`) + additive Unix Domain Socket IPC daemon control server (`randbotctl peer import`), enabling dynamic runtime peer importing. | 🟢 |
| `NET-09` | **Peer Reflection Probe & IP Privacy Enforcement** | P2P reflection probe protocol (`PAYLOAD_TYPE_REFLECT_ADDR_REQ`/`RESP`) allowing nodes to discover their external socket address directly from peers without STUN or third-party web APIs. Includes `--do-not-advertise-ip` / `do_not_advertise_ip` CLI/config protection emitting mandatory operator warnings if clearnet IP advertising compromises privacy. | 🟢 |

---

## 🔑 2. Root & Intermediate CA Engine (`Publish CA`)

| Feature ID | Module Name | Description | Status |
| :--- | :--- | :--- | :---: |
| `CA-01` | **Custom Subject Metadata Engine** | Configurable creation of root/intermediate CAs with custom Subject Name, Emissor, O, and OU fields. | 🔴 |
| `CA-02` | **Cryptographic Agility Suite** | Multi-algorithm key generation and certificate signing: RSA-4096, ECDSA P-384, and Ed25519. | 🔴 |
| `CA-03` | **Multi-Network Domain Proofs** | Verification of domain control via DNS TXT, Handshake record, Tor HTTP/TLS-ALPN, and I2P LeaseSets. A CA must have the corresponding daemon configured (`tor`/`i2p`/`hnsd`) to advertise support for that proof method — advertising a network type without a working backend is rejected at startup. Includes an **HTTP Nonce Fallback** for operators without direct access to their DNS zone (clearnet or Handshake): the CA emits a short-lived nonce, the node signs it with its P2P Ed25519 identity key and serves the signature under a well-known path (e.g. `/.well-known/randbotd-proof`); the CA fetches and verifies the signature against the known node public key, providing a cryptographically safe proof of domain control without DNS access. | 🔴 |
| `CA-04` | **P2P Cert Chain Broadcasting** | Automated broadcast of published CAs, intermediate cert chains, and CRLs across the P2P swarm. | 🔴 |
| `CA-05` | **X.509 Certificate Builder** | Standard-compliant X.509 v3 certificate builder with custom extensions for WoT signatures. | 🔴 |
| `CA-06` | **CA Command Center Dashboard** | Management control plane for CA operators to monitor domain health, issue CRLs, rotate keys, and analyze trust metrics. | 🔴 |
| `CA-07` | **Bad-Domain Purge Engine** | Allows CAs to broadcast UTW domain purge requests. Every purge request is independently validated by recipient local nodes against PoW/strike evidence; un-substantiated or fraudulent purges emitted by CAs are rejected locally by user nodes, leaving lying CAs in a solipsistic state. | 🔴 |
| `CA-08` | **Configurable Certificate Parameters (Custom TTL)** | Allows CAs to specify custom issuance parameters, such as custom certificate validity/TTL (Time-To-Live). | 🔴 |
| `CA-09` | **Cryptographic Key Rotation & Remediation Engine** | Allows CAs to publish signed `KeyRotationProof` payloads to revoke compromised key material and reset standing key-compromise flags following market distrust strikes. | ⚪ |
| `CA-10` | **Critical Custom X.509 OID Extension Engine (`randbotd-WoT-Validation-Extension`)** | Embeds a custom X.509 extension marked `critical = TRUE` using ITU-T X.667 decentralized UUID OID `2.25.332006307751889903095271628869501346770.1.1`. Ensures voluntary opt-in and prevents free-riding (un-augmented legacy browsers automatically reject native certs unless users explicitly install an extension or proxy daemon), enables client tools to spot native certs, and neutralizes stolen/unpaid certs both inside (blocked by P2P `TxKeyProof` consensus) and outside (blocked by RFC 5280 Critical OID semantics). | ⚪ |
| `CA-11` | **Distributed Custodian Swarm & Threshold Key Delegation Engine** | Enables CAs to distribute operational load and key signing across $n$ decentralized nodes using threshold cryptography (FROST / $m$-of-$n$ Schnorr/Ed25519 DKG). Includes `CustodianDelegationProof` payloads for delegating short-lived operational issuance rights to worker nodes while protecting root key material. | ⚪ |
| `CA-12` | **Multi-Tier CA Certificate Offer Catalog & Profile Engine** | Replaces single static pricing with a structured Offer Catalog (`CAPublishOfferCatalog`). Allows CAs to publish multiple `CertificateProfile` options (e.g. Profile 0: Free Standard short-TTL, Profile 1: Multi-SAN/Wildcard, Profile 2: Long-TTL Enterprise) seamlessly integrated with client `--free-only` and `account_price_ceiling` filters. | ⚪ |
| `CA-13` | **Cryptographic Certificate Serial Entropy Engine** | Standard-compliant generator (RFC 5280 / CABF BR §7.1.4.2.1) injecting 64-160 bits of CSPRNG entropy into X.509 certificate serial numbers (`CertificateSerialNumber`) to immunize certificate issuance against hash collision and serial prediction attacks. | 🔴 |
| `CA-14` | **Subtree Name Constraints Engine (`permittedSubtrees`/`excludedSubtrees`)** | Standard-compliant implementation of X.509 v3 Name Constraints extension (RFC 5280 §4.2.1.10) marked `critical = TRUE`. Allows Intermediate CAs to be cryptographically restricted to specific domain namespaces (e.g., strictly `.hns`, `.onion`, `.i2p`, or specific domain subtrees). | 🔴 |
| `CA-15` | **P2P Authority Information Access (AIA) & P2P OCSP Engine** | Extends RFC 5280 AIA extension (`1.3.6.1.5.5.7.1.1`) with `randbotd://` P2P swarm URIs for fetching parent CA cert chains (`caIssuers`) and checking real-time P2P revocation status (`id-ad-ocsp`) directly over gossip without central Web server dependencies. | 🔴 |


### 📋 CA Module Implementation Order

Implementation phases, ordered by dependency and foundational priority:

| Phase | Features | Rationale |
| :--- | :--- | :--- |
| **Phase 1** | `CA-01`, `CA-02`, `CA-03`, `CA-08`, `CA-10`, `CA-12`, `CA-13`, `CA-14` | Core identity, metadata, and proof primitives. CA creation, cryptographic key generation, domain proof engine (with capability enforcement + HTTP nonce fallback), custom TTL parameters, offer catalog structure (`CA-12`), serial entropy (`CA-13`), name constraints (`CA-14`), and the WoT critical OID extension. No CA can be issued or trusted without these foundations. |
| **Phase 2** | `CA-05`, `CA-15` | X.509 certificate builder depends on Phase 1 keys, proof results, TTL parameters, offer profiles, and OID extensions being fully defined. Integrates P2P AIA/OCSP extension (`CA-15`). |
| **Phase 3** | `CA-04`, `CA-07`, `CA-09`, `CA-11` | P2P broadcast, bad-domain purge, key rotation, and distributed custodian threshold swarm (`CA-11`) all depend on valid certificates existing in the system and the cert builder being operational. |
| **Phase 4** | `CA-06` | Dashboard and control plane are the operational layer built on top of a fully working CA engine. |

> **Architectural note (OCP):** The CA issuance pipeline must be designed open for extension, closed for modification. `PAY-01` (CA Optional Service Fee Publisher) will slot optional pricing into the CA engine without altering core issuance logic — keep the CA data structures and issuance flow decoupled from payment so that adding a `price` field or fee validation step requires no rewrites.

---

## ⚖️ 3. Reputation & Web-of-Trust Engine (`Vote TW / UTW`)

| Feature ID | Module Name | Description | Status |
| :--- | :--- | :--- | :---: |
| `REP-01` | **Proof-of-Work Challenge Engine** | Dynamic PoW puzzle generator (SHA-256 / Equihash) required for vote submission. | 🔴 |
| `REP-02` | **1-Vote-Per-Node Dynamic Voting** | State machine enforcing 1 active vote per node per domain with real-time mind-changing support. | 🔴 |
| `REP-03` | **Behavioral Score & Weight Ponderation** | Historical voter reputation engine scaling down voting power for detected review-bombers/Sybil nodes. | 🔴 |
| `REP-04` | **Lazy Evaluation Engine** | On-demand computation of domain/CA trust scores and $\Delta$ windows. Automatically rescales $\Delta$ when active network node count $N_{\text{active\_nodes}}$ expands. | 🔴 |
| `REP-05` | **CA Rating Propagation Engine** | Calculation of a CA's public rating as the weighted average of trust scores of all issued domains. | 🔴 |
| `REP-06` | **Bi-Directional Image Cleaning** | Mechanisms for CAs to boost rating via domain revocations, and domains to recover from review-bomb strikes. | 🔴 |
| `REP-07` | **Heuristic Cluster Ponderation Penalties** | Detects behavioral collusion rings and suspicious voting correlation. Invalid network interactions (e.g. fraudulent purges) degrade the voter ponderation of the offending node AND all heuristically linked cluster nodes. | 🔴 |
| `REP-08` | **PoW User CA Flagging Engine (`Signal CA`)** | Allows end users to launch PoW-backed, weighted suspicion flags directly against CA identities. Does not immediately degrade CA trust score; decays exponentially via time half-life unless sustained. Triggers `NOTIF-01` domain inbox alerts upon crossing network threshold $T_{\text{warn}}$. | ⚪ |
| `REP-09` | **Market Signal of Distrust & Early Renewal Punishment** | Enables domain owners to execute early cert renewals tagged with `reason: DistrustSignal`. Burns remaining TTL + ACME fee (replacing PoW) to issue a permanent, non-decaying direct UTW strike to the CA. Strike weight scales dynamically: $W_{\text{distrust}} = f(\text{TTL}_{\text{remaining}}, \text{Fee}_{\text{paid}}, \text{Flag}_{\text{level}})$. | ⚪ |

---

## 🎯 4. Fair-Band ACME Certificate Allocation (`GetCert`)

| Feature ID | Module Name | Description | Status |
| :--- | :--- | :--- | :---: |
| `ACME-01` | **ACME v2 Protocol Adapter** | RFC 8555 compliant endpoints (`/acme/directory`, `/acme/new-order`, `/acme/finalize`). | 🔴 |
| `ACME-02` | **50% Baseline Initializer** | Initializing new domains and CAs at a neutral 50% baseline score with 0 votes ($\Delta = \pm 50\%$). | 🔴 |
| `ACME-03` | **Randomized Fair-Band Matching ($\pm \Delta$)** | Matching domain cert requests to CA pools within dynamic confidence tolerance window ($\pm \Delta$). | 🔴 |
| `ACME-04` | **Logarithmic Dynamic Delta ($\Delta$) Engine for CA Matching** | Used specifically during certificate generation (`GetCert`) to compute matching tolerance ($\pm \Delta$) between domain and candidate CAs. Starts at $\pm 50\%$ for 0 votes and decays logarithmically based on vote count vs $N_{\text{active\_nodes}}$ (domain votes for domain $\Delta$; P75 domain vote ensemble for CA $\Delta$). Clipped at $[0\%, 100\%]$ and $\Delta \ge 0$, naturally widening on lazy evaluation as network node count grows. | 🔴 |
| `ACME-05` | **CA Operator Risk Floor Configurator** | Allows CAs to set custom minimum reputation acceptance thresholds (`risk_floor`) extending risk acceptance downward below their dynamic lower confidence bound ($50\% - \Delta$) to host dissident/lower-reputation domains. Setting a floor above lower $\Delta$ to cherry-pick high-score domains ("domain-fishing fraud") is strictly prohibited and rejected by fair-band matching. | 🔴 |
| `ACME-06` | **Emergency Default Fallback CA** | Provisions temporary, short-TTL certificates if a randomly matched P2P CA is currently offline, ensuring zero downtime while waiting for full issuance. | 🔴 |
| `ACME-07` | **`--only-online` Filter Selection** | Client flag allowing domain owners to restrict fair-band matching strictly to active/online CAs for immediate cert issuance (lowers pool size). | 🔴 |
| `ACME-08` | **Do-Not-Match (DNM) CA Exclusion Filter (`--dnm <CA_ID>`)** | Client flag during certificate allocation (`GetCert`) enabling domain owners to pass explicit CA exclusion filters (`--dnm`). Excludes flagged/distrusted CAs from fair-band matching. If no alternative candidate CAs exist in the domain's current free Fair-Band pool, allocation defaults back to the existing CA unless the domain owner raises their price ceiling (`account_price_ceiling`), driving organic demand for paid CA tiers. | ⚪ |

---

## 🌐 5. Out-Of-Net Trust Substitution & Foreign Certificate Engine

| Feature ID | Module Name | Description | Status |
| :--- | :--- | :--- | :---: |
| `OUT-01` | **System Trust Store Substitution** | Engine allowing `randbotd` to substitute or augment default OS / browser trusted root certificate stores. | 🔴 |
| `OUT-02` | **Foreign Certificate Ingestion** | Support for ingesting self-signed certificates, Caddy internal CA certs, and traditional ICANN certificates. | 🔴 |
| `OUT-03` | **`out-of-net` Cryptographic Marking** | Mandatory tagging and isolation of foreign/ICANN/self-signed certs as `out-of-net` to distinguish them from native peer-voted `randbotd` CAs. | 🔴 |
| `OUT-04` | **Browser Extension & Proxy Delegation Engine (Protocol Agnostic)** | Protocol-agnostic client delegation interface. `randbotd` provides consensus mathematics, WoT rating evaluation, and `out-of-net` classification without imposing rigid client parsing. Browser extensions and proxy plugins can either pre-filter via the critical OID (`2.25.332006307751889903095271628869501346770.1.1`) or delegate 100% of TLS certificate evaluation, store substitution, and consensus checking directly to the local `randbotd` daemon via gRPC/REST (`ECO-04`). | ⚪ |

---

## 📬 6. Proactive Early Warning & Inbox System

| Feature ID | Module Name | Description | Status |
| :--- | :--- | :--- | :---: |
| `NOTIF-01` | **Domain Owner Inbox Alerts** | Automated P2P notification sent to TW domain owners when their hosting CA drops into UTW status. | 🔴 |
| `NOTIF-02` | **CA Operator Strike Notifications** | Alerting CA operators immediately when an issued domain receives an UTW strike. | 🔴 |
| `NOTIF-03` | **Encrypted P2P Messaging Queue** | Asynchronous end-to-end encrypted inbox messaging channel between network nodes. | 🔴 |

---

## 🔌 7. Ecosystem Integration & Public Tools

| Feature ID | Module Name | Description | Status |
| :--- | :--- | :--- | :---: |
| `ECO-01` | **Caddy CertMagic Plugin** | Native Golang/Caddy plugin enabling seamless TLS auto-renewal via `randbotd` ACME endpoints. | 🔴 |
| `ECO-02` | **`bullshiters.randºm` Public Portal & Recruitment Engine** | Public cryptographic shaming index targeting `out-of-net` legacy domains and CAs (Let's Encrypt, DigiCert, ICANN). Native nodes receive direct P2P inbox alerts, while `bullshiters.randºm` serves as a public shaming wall and second-hand recruitment portal for both legacy CAs ("ok, let's try that cypherpunk shit") and domain owners to migrate keys into randbotd P2P WoT consensus, kick bad domains, and participate in peer-voted encryption under the manifesto: *"This list has not been emitted by any central authority. We do not apologize, we do not revoke network consensus. To clean your image, just migrate to randbotd: if you use your same keys you will automatically be synced and you can start kicking bad domains and participate in real open and public encryption. Internet by the people, for the people."* | 🔴 |
| `ECO-03` | **`randbotctl` CLI & CA Command Center** | Command-line interface for daemon control, CA publication, voting, domain purges, and reputation lookup. | 🔴 |
| `ECO-04` | **gRPC & REST Daemon APIs** | Local API endpoints for system integrations and client control. | 🔴 |

---

## 💸 8. Monero (XMR) Decentralized Market & Escrow-less Settlement Engine

| Feature ID | Module Name | Description | Status |
| :--- | :--- | :--- | :---: |
| `PAY-01` | **CA Optional Service Fee Publisher** | Allows CAs to optionally publish a service fee (in XMR) alongside their issuance parameters. Market-driven pricing (default free). | 🔴 |
| `PAY-02` | **In-Bot Monero Wallet Integration** | Embedded Monero wallet module for automated fee deductions directly to the issuing CA's address communicated during cert negotiation. | 🔴 |
| `PAY-03` | **3-Step Escrow-less Fraud Prevention & Monero `tx_key` Proofs** | 3-step cryptographic smart contract settlement (`ContractConstitution` $\rightarrow$ `CertEmission` $\rightarrow$ `TxKeyProof`). Network peers independently verify that emitted cert matches constituted terms and Monero `tx_key` proves on-chain fee payment before validating P2P log entry. Prevents local client forgery (a rogue client or CA modifying local binary to fake payment or issuance lives in a solipsistic parallel universe rejected by P2P consensus). | 🔴 |
| `PAY-04` | **Account Price Ceiling & Balance Protection** | Configurable `account_price_ceiling` preventing requests to CAs priced above ceiling, with auto-matching restricted to balance $\ge$ fee. | 🔴 |
| `PAY-05` | **`--free-only` Client Override Flag** | Client flag enforcing strict 0-cost / free CA matching on a per-call basis regardless of account balance or price ceiling. | 🔴 |
| `PAY-06` | **Anti-Purge Fraud Game Theory Engine** | Enforces mathematical purge pricing: `Purge Cost = Remaining Prorated Fee - Reputational Cost Deduction`. CAs purging UTW-heavy bad domains purge for free (0 cost) due to high reputational deductions; early purging of clean domains requires refunding the remaining prorated fee. Invalid purges bypassing payment are rejected by P2P consensus, preserving cert validity. | 🔴 |

---

## 🛡️ 9. Classical Attack Mitigation Matrix

| Attack Vector | Threat Description | Defense & Cryptographic Countermeasure |
| :--- | :--- | :--- |
| **Bait-and-Switch** | CA delivers incorrect cert type, lower TTL, or weaker algorithm after payment. | Covered by **Atomic Smart Contract Settlement** (`PAY-03`). Contract specifies exact cert metadata, parameters, and TTL; funds release only upon cryptographic proof of matching cert. |
| **Reputation Farming / Sybil** | Malicious entities spawn fake nodes to inflate domain/CA trust ratings artificially. | Covered by **Behavioral Ponderation & Cluster Penalties** (`REP-03`/`REP-07`). 1 vote per node, PoW puzzle verification, and heuristic cluster ponderation degradation for correlated voting rings. |
| **Vendor Lock-In** | Paid CAs attempt to force domain owners into recurring proprietary renewals. | Covered by **Pool Renewal & Price Ceilings** (`ACME-03`/`PAY-04`). Renewals are matched dynamically against the full fair-band CA pool with client-side `--free-only` and `account_price_ceiling` enforcement. |
| **Purge Extortion / Rug-Pull** | CA takes payment then revokes certificate prematurely without justification. | Covered by **Anti-Purge Game Theory & Consensus Enforcement** (`PAY-06`). Prorated fee refunds are enforced mathematically; invalid purges are rejected by P2P consensus, keeping certs valid locally. |
| **Collusion / Cluster Manipulation** | Coordinated node ring voting deceptively to shield a corrupt CA's rating. | Covered by **Heuristic Cluster Ponderation Penalties** (`REP-07`). Invalid network actions degrade the voter weight of the offending node AND all behaviorally correlated cluster nodes. |
| **Rogue CA / Key Leak / Decryption Fraud** | CA exhibits infrastructure fraud, compromised keys, or unauthorized secret sharing. | Covered by **PoW User CA Flagging & Market Distrust Strikes** (`REP-08`/`REP-09`). Users raise decaying PoW flags alerting domain owners (`NOTIF-01`) who emit permanent non-decaying market distrust strikes by renewing early. Remediated via **Cryptographic Key Rotation** (`CA-09`). |

---

## 📈 Roadmap Execution Order

```mermaid
graph TD
    A["Phase 0: Repository & Infrastructure Setup"] --> B["Phase 1: Cryptographic Primitives, Multi-Hop P2P & History Sync"]
    B --> C["Phase 2: Logarithmic Delta Engine (Domains & P75 CAs)"]
    C --> D["Phase 3: CA Command Center & Domain Purge Engine"]
    D --> E["Phase 4: Reputation & Web-of-Trust Engine"]
    E --> F["Phase 5: ACME Server, Fair-Band Matching & Offline Fallbacks"]
    F --> G["Phase 6: Out-of-Net Store Substitution & Foreign Cert Marking"]
    G --> H["Phase 7: Early Warning System & Caddy Plugin"]
    H --> I["Phase 8: Public Shaming Index (bullshiters.randºm)"]
    I --> J["Phase 9: Monero Decentralized Market & Escrow-less Settlement Engine"]
```
