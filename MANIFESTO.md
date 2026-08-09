# 🛡️ The `randbotd` Manifesto
### *Decentralized Trust, Network Sovereignty & Monopolyless Web PKI*

---

## 📜 1. The Hegemony of Modern Web PKI

The modern internet relies on transport encryption (TLS/SSL) to secure human communication, commerce, and identity. However, the foundational trust architecture of the World Wide Web—the Public Key Infrastructure (PKI)—is fundamentally broken and centralized.

Today, a small cartel of Certificate Authorities (CAs) and corporate browser vendors dictate who is allowed to speak, host, and encrypt content on the web. Legacy ICANN CAs (Let's Encrypt, DigiCert, Sectigo) hold absolute power over global trust:
* **Arbitrary Revocation & Censorship:** Centralized entities can unilaterally revoke certificates, de-platform domains, or deny TLS issuance based on geopolitical mandates or corporate policies.
* **Single Points of Failure:** Compromise, coercion, or misissuance by a single recognized CA undermines the security of the entire global web.
* **ICANN-Only Monopoly:** Alternative, sovereign, and privacy-preserving networks—such as **Handshake (`.hns`)**, **Tor (`.onion`)**, and **I2P (`.i2p`)**—are treated as second-class citizens or outright denied certificate issuance by traditional CAs.

We reject a web where encryption is gated by centralized gatekeepers. **Transport security is a fundamental right, not a corporate privilege.**

---

## ⚡ 2. The Core Philosophy of `randbotd`

`randbotd` was created to dismantle legacy CA monopolies and replace centralized trust with a **peer-to-peer, consensus-driven Web-of-Trust (WoT) engine**.

### I. Trust is Earned, Not Granted
Trust cannot be bought with money, corporate validation, or ICANN domain registry approval. In `randbotd`, network trust emerges dynamically through continuous, peer-evaluated cryptographically verifiable voting.

### II. Multi-Network Equality
Decentralized identity requires decentralized transport security. `randbotd` treats **Handshake (`.hns`)**, **Tor (`.onion`)**, **I2P (`.i2p`)**, and traditional clearnet domains with equal cryptographic dignity. No root CA should have the power to decide which top-level domain or hidden service is worthy of TLS encryption.

### III. Cryptographic Agility
Static algorithms become single points of systemic failure. `randbotd` enforces cryptographic agility across RSA-4096, ECDSA P-384, and Ed25519 primitives, enabling smooth protocol evolution and resistance to cryptographic degradation.

### IV. The Myth of the "Leecher": Infrastructure Nodes as Network Citizens
In traditional P2P networks, non-voting or headless nodes are often labeled as "leechers". In `randbotd`, **no node is a true leecher**. Even an automated daemon running in headless mode (`--mode=headless`) on a home server—which never browses, casts votes, or evaluates domain reputation—actively serves the ecosystem by relaying multi-hop P2P gossip messages, verifying Proof-of-Work challenges, propagating CA cert chains, and reinforcing swarm topology. We accommodate infrastructure nodes natively by isolating them from voter pool calculations ($N_{\text{active\_voter\_nodes}}$) and behavioral heuristics, ensuring that server infrastructure strengthens the network without degrading reputation math.

### V. Lean Daemon Philosophy: Proxy Delegation Over Monolithic Bundling
Keeping `randbotd` lean is a deliberate architectural and philosophical choice. We explicitly reject bundling or embedding heavy privacy network runtimes (such as Tor daemons or I2P routers) into `randbotd`. Unlike monolithic browser suites (e.g., Juanita Banana), `randbotd` operates as a lightweight, single-purpose Unix daemon. It exposes simple configuration parameters (`tor_socks_proxy`, `i2p_proxy_port`, `sam_port`) so node operators can direct network traffic through their existing, independently managed local privacy proxies. This preserves process isolation, minimizes attack surface, avoids redundant resource consumption, and respects the Unix philosophy of doing one thing well.

---

## ⚖️ 3. Architectural Tenets

### 1. Dynamic Web-of-Trust (`Vote TW / UTW`)
* **1 Active Vote per Node**: Every participant node holds exactly one active vote per domain (**TW** - Trustworthy or **UTW** - Untrustworthy).
* **Proof-of-Work & Behavior Ponderation**: To eliminate vote-stuffing and review-bombing, votes require Proof-of-Work (PoW) computation and are weighted by the voter's historical network behavior score. Sybil attackers and malicious review-bombers burn computational power only to have their voter weight reduced to zero.
* **Lazy Evaluation**: Reputation scores are evaluated dynamically on-demand, reflecting real-time network sentiment and domain behavior.

### 2. Fair-Band ACME Certificate Allocation (`GetCert`)
* **Neutral 50% Baseline**: All new domains and newly published CAs enter the ecosystem at a neutral 50% baseline score with 0 votes ($\Delta = \pm 50\%$), ensuring a level playing field for new entrants.
* **Logarithmic Dynamic Confidence Window ($\pm \Delta$)**:
  * **Starting Baseline**: At 0 votes, $\Delta = \pm 50\%$, spanning the full spectrum $[0\%, 100\%]$.
  * **Logarithmic Decay Curve**: As vote count grows relative to total active network nodes ($N_{\text{active\_nodes}}$), $\Delta$ shrinks along a logarithmic envelope, dropping rapidly at first and narrowing toward the entity's true consensus trust value.
  * **Domain $\Delta$ Formula**: $\Delta_{\text{domain}} = \pm 50\% \times f\left(\frac{N_{\text{votes}}}{N_{\text{active\_nodes}}}\right)$, where $f$ is the logarithmic decay function clipped at $\Delta \ge 0$.
  * **CA Ensemble $\Delta$ Formula**: A CA's vote volume is evaluated across the ensemble of all domains issued under its authority, taking the 75th percentile (P75) vote count: $\Delta_{\text{CA}} = \pm 50\% \times f\left(\frac{\text{P75}(\{N_{\text{votes}}(\text{domain}_i)\})}{N_{\text{active\_nodes}}}\right)$.
  * **Boundary Clipping**: All reputation bounds and confidence windows are strictly clipped to $[0\%, 100\%]$, ensuring $\Delta$ never turns negative.
  * **Dynamic Rescaling via Lazy Evaluation**: Because evaluation is performed lazily on-demand, as the active network node count $N_{\text{active\_nodes}}$ expands, the ratio naturally drops, causing $\Delta$ to widen dynamically for stale entities until new votes arrive.
* **Opt-In Risk Floors**: CA operators retain sovereignty to adjust their accepted risk floor, enabling courageous nodes to host high-risk, censorship-resistant, or dissident domains while taking accountability for their aggregate CA reputation.

### 3. Resilience, Multi-Hop Sync & Offline Resilience
* **Multi-Hop Gossip & Node-Bound Hybrid Catch-Up Log**: Unlike single-hop gossip implementations, `randbotd` employs multi-hop P2P gossip to propagate real-time events network-wide. Reconnecting or offline peers synchronize missing historical event logs through a **Node-Bound Integer + Linked Hash Hybrid Log** (`seq`, `prev_hash`). Peers exchange compact node-scoped range vectors (`Node_A: [1..N]`) and resolve sequence gaps using a self-terminating ping-pong range intersect protocol (with Merkle root fallback for heavy fragmentation), achieving full anti-entropy sync with zero blockchain or coin overhead.
* **Offline CA Fallback & Immediate Selection**: To ensure zero downtime when a fair-band matched P2P CA is offline, `randbotd` provides emergency default temporary certificates (short-TTL) or allows clients to opt for `--only-online` CA pool matching for immediate cert delivery.
* **CA Command Center & Active Purging**: CA operators maintain control planes to inspect domain metrics and actively purge UTW domains to defend CA network image (prompting affected domains to perform early renewal).

### 4. Radical Accountability, Out-Of-Net Isolation & Second-Hand Recruitment
* **Out-Of-Net Certification Isolation**: `randbotd` can substitute local system certificate stores. External sources—including self-signed certs, Caddy internal CAs, and legacy ICANN CAs—are accepted but strictly marked as **`out-of-net`** to differentiate them from peer-voted `randbotd` native CAs.
* **CA & Domain Image Cleaning**: CAs elevate their rating by purging abusive domains; domains recover standing by accumulating positive consensus and shedding malicious strikes.
* **Cryptographic Shaming & Recruitment Portal (`bullshiters.randºm`)**: Non-randbotd CAs and abusive `out-of-net` domains flagged as Untrustworthy (UTW) by network consensus are publicly indexed on a cryptographic shaming portal. It operates under an unyielding manifesto:
  > *"This list has not been emitted by any central authority. We do not apologize, we do not revoke network consensus. To clean your image, just migrate to randbotd: if you use your same keys you will automatically be synced and you can start kicking bad domains and participate in real open and public encryption. Internet by the people, for the people."*
  
  This portal serves as a second-hand recruitment engine for both legacy CAs (*"ok, let's try that cypherpunk shit"*) and domain owners to adopt peer-voted Web-of-Trust consensus.

### 5. Cypherpunk Market Economics: "Being Cypherpunks Doesn't Mean Being Hobos"
* **Free-Market Pricing Dynamics**: Being cypherpunks does not require living as hobos or relying on corporate charity. CA operators may voluntarily attach service fees (in Monero / XMR) to certificate issuance while letting open market competition dictate pricing. While free/0-cost issuance will still rule the world, sustainable infrastructure requires economic choice.
* **In-Bot Monero Wallet & Escrow-Less Settlement**: Automated P2P fee settlement directly between in-bot Monero addresses using cryptographic proof-of-issuance smart contracts, eliminating fraud without third-party escrows.
* **Client Sovereignty & Price Protection**: Domain owners retain absolute control via configurable `account_price_ceiling` settings, wallet balance safeguards, and `--free-only` flags to enforce zero-cost CA matching on demand.
* **Anti-Purge Fraud Game Theory & P2P Consensus Enforcement**: To eliminate "Purge Before TTL Fraud" (where a paid CA takes a fee and arbitrarily revokes a certificate), the cost for a CA to purge an active certificate before TTL expiration is mathematically enforced by the network:
  $$\text{Purge Cost} = \text{Remaining Prorated Fee} - \text{Reputational Cost Deduction}$$
  If a domain receives heavy UTW strikes from weighted trusted nodes, high reputational cost deductions make image-cleaning purges **free** for the CA. However, purging a clean domain before TTL expiration requires refunding the remaining prorated fee. If a rogue CA modifies daemon code to bypass fee settlement, P2P network consensus **rejects the purge event broadcast**, keeping the domain's certificate valid across all peer nodes locally.
* **Invalid Interaction & Heuristic Cluster Penalties**: Any invalid network interaction—such as broadcasting a fraudulent purge without paying required refunds or emitting malformed P2P actions—degrades the voter ponderation (behavioral weight) of the offending node AND all peer nodes identified by heuristics as a correlated cluster (nodes displaying suspicious voting patterns towards the CA's domains or similar behavioral signatures).
* **Cryptographic Immunity to Classical Attacks**:
  * **Bait-and-Switch**: Prevented by atomic smart-contract settlement specifying exact cert algorithms, metadata, and TTL before fee release.
  * **Reputation Farming / Sybil**: Neutralized by PoW verification, 1-vote-per-node limits, and dynamic behavioral ponderation.
  * **Vendor Lock-in**: Rendered impossible by design because certificate renewals are allocated against the dynamic fair-band CA pool under client-enforced price ceilings (`--free-only` / `account_price_ceiling`).

### 6. Overlay Privacy Networks, Do-Not-Advertise Isolation & Phonebook Discovery
* **IP-to-IP Swarm Reality & Overlay Boundaries**: All P2P gossip and node-to-node communication in `randbotd` takes place directly IP-to-IP over standard TCP/UDP sockets, unless explicitly routed through Tor/I2P overlay proxies. Decentralized top-level domains like `.hns` represent identity/reputation entities evaluated within the Web-of-Trust, not distinct network transport protocols.
* **Do-Not-Advertise IP Config (`do_not_advertise_ip`)**: Nodes seeking anonymity can instruct `randbotd` to suppress broadcasting their public IPv4/v6 addresses to the P2P swarm, advertising `.onion` or `.i2p` hidden service addresses exclusively.
* **Overlay Peer Discovery & Phonebook Sharing**: Because Tor exit nodes and I2P outproxies strictly restrict unprompted inbound P2P connections to common client ports (`80`, `443`, `22`), traditional clearnet peer discovery sweeps fail. `randbotd` solves hidden node discovery through P2P phonebook (address book) list exchange between connected peers paired with explicit manual peer importing (`randbotctl peer import` / seed configs).

### 7. Dual-Layer CA Accountability: Community Signaling & Economic Proof-of-Distrust
* **User CA Flagging (`Signal / Flag CA`)**: End users evaluate CA infrastructure directly using Proof-of-Work (PoW) backed flags. User flags do not instantly alter a CA's baseline trust score, preventing mob review-bombing of innocent domains. Because user flags carry no direct financial cost, they decay exponentially over time unless continuously re-enacted by community PoW. Crossing a network flag threshold triggers proactive P2P inbox alerts (`NOTIF-01`) to all hosted domain owners.
* **Economic Market Signals of Distrust & DNM Filters**: Domain owners hold direct contracts with CAs. Upon receiving community warning flags or detecting CA misbehavior, a domain owner can execute an early certificate migration (`GetCert` with `reason: DistrustSignal` and `--dnm <CA_ID>`). By abandoning valid TTL and burning ACME issuance fees, the domain owner emits an un-forgeable **Market Signal of Distrust**. Money and TTL burn replace PoW, producing a permanent, non-decaying reputational strike against the CA. The strike weight scales dynamically: $W_{\text{distrust}} = f(\text{TTL}_{\text{remaining}}, \text{Fee}_{\text{paid}}, \text{Flag}_{\text{level}})$.
* **Fair-Band DNM Pool Exhaustion & Paid Tier Demand**: When a domain owner specifies a Do-Not-Match (`--dnm`) filter to abandon a low-TTL or distrusted CA, Fair-Band matching attempts to allocate a new CA within the domain's confidence window ($\pm \Delta$). If no alternative candidate CAs exist in the free tier of that band, the matching algorithm defaults back to the existing CA. To guarantee migration away from the excluded CA, the domain owner must increase their price ceiling (`account_price_ceiling`), spending higher to access commercial CA pools. This ties together protocol accountability and cypherpunk market economics without creating free-lunch vulnerabilities.
* **Cryptographic Remediation**: CAs cannot passively wait out market distrust strikes. To remediate standing strikes, CAs must publish cryptographically verifiable **Key Rotation Proofs** (`KeyRotationProof`) revoking compromised key material, or attract high-reputation TW domains to stay and vouch for their infrastructure.

---

## 🌐 4. Our Pledge to the Future Web

`randbotd` is built under the **Mozilla Public License 2.0 (MPL-2.0)**. It belongs to no single corporation, nation-state, or foundation. It is an open-source, peer-to-peer daemon engineered to ensure that:

1. **Every website, hidden service, and decentralized domain can be encrypted without permission.**
2. **Every Certificate Authority is subject to peer consensus and dynamic reputation.**
3. **The web remains open, resilient, sovereign, and censorship-resistant.**

*Freedom to encrypt. Freedom to trust. Freedom from gatekeepers.*
