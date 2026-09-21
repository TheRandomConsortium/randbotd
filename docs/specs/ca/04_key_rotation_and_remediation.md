# 🔄 `CA-09` Cryptographic Key Rotation & Remediation Engine
### *Specification & Operational Architecture: Offer Key Lifecycle, Proof-of-Possession, Distrust Remediation & Anti-Solipsism*

---

## 1. Architectural Foundations: Offer-Level Keys vs. Node CA Identity

In `randbotd`, a Certificate Authority (CA) entity is fundamentally decoupled from a single static certificate-signing key:

```
+-----------------------------------------------------------------------------------+
|                            CA Cryptographic Architecture                          |
+-----------------------------------------------------------------------------------+
| 1. Sovereign CA Identity (Immutable Anchor)                                       |
|    - ca_id: SHA-256("randbotd_v1_ca_identity_domain:" || CN || ":" || node_pubkey) |
|    - Managed by owner node identity key (Ed25519)                                 |
|    - Signs declarations: Offer Catalogs, Domain Purges, and KeyRotationProofs     |
+-----------------------------------------------------------------------------------+
| 2. Certificate Offers (Operational Issuance Keys)                                 |
|    - Offer 0: Ed25519 (e.g. Free Clearnet, 90d TTL)           -> Has Keypair 0    |
|    - Offer 1: ECDSA P-384 (Multi-SAN Wildcard, 180d TTL)      -> Has Keypair 1    |
|    - Offer 2: RSA-4096 or ML-DSA-44 (Enterprise, 365d TTL)    -> Has Keypair 2    |
+-----------------------------------------------------------------------------------+
```

Because a CA does NOT sign leaf certificates with its node key, but rather with the key assigned to the corresponding **Certificate Offer** (`CertificateOffer`), key rotation operates at the **Offer Level**.

---

## 2. Operational Dimensions of Key Rotation

Key rotation in `randbotd` serves two distinct operational requirements:

### A. Targeted / Operational Rotation (Routine Hygiene & Suspected Leaks)
- An operator may rotate the key of a single offer (or any subset of offers) without affecting other offers.
- **Valid Reasons**:
  - `RoutineOperational`: Periodic scheduled replacement for cryptographic hygiene.
  - `SuspectedLeakage`: Proactive rotation upon suspected side-channel exposure or infrastructure vulnerability.
  - `CompromisedKey`: Emergency replacement following verified compromise of an offer private key.
- **Scope**: Can rotate 1 or $k$ offers. Does not require rotating unimpacted offers.

### B. Distrust Strike Remediation (Resetting Market Distrust under `REP-09`)
- When a CA suffers market distrust strikes (`DistrustStrike`) or standing key-compromise flags from domain migrations (`reason: DistrustSignal`), the CA cannot passively wait out the penalty.
- **The Distrust Reset Invariant**:
  > [!IMPORTANT]
  > To remediate standing market distrust strikes and reset key-compromise flags, a `KeyRotationProof` **MUST prove rotation of ALL keys across ALL active (non-draft) offers** belonging to the CA.
  > If any active offer is omitted from the proof, standing distrust strikes remain active.

---

## 3. Cryptographic Structure: `KeyRotationProof`

A `KeyRotationProof` is a cryptographically chained payload structured as follows:

```rust
pub struct KeyRotationProof {
    pub proof_id: [u8; 32],
    pub ca_id: [u8; 32],
    pub rotation_seq: u64,
    pub prev_rotation_hash: [u8; 32],
    pub timestamp: u64,
    pub reason: RotationReason,
    pub rotations: Vec<OfferKeyRotation>,
    pub ca_signature: Vec<u8>,
}
```

### 3.1 Offer Key Rotation Item & Proof-of-Possession (PoP)

Each rotated offer item is defined as:

```rust
pub struct OfferKeyRotation {
    pub offer_id: u32,
    pub old_public_key: Vec<u8>,
    pub new_public_key: Vec<u8>,
    pub key_algorithm: KeyAlgorithm,
    pub proof_of_possession: Vec<u8>,
    pub old_key_revocation_signature: Option<Vec<u8>>,
}
```

1. **Proof-of-Possession (PoP)**:
   - To prevent an attacker or malicious node from claiming public keys it does not control, the *new* keypair must sign the canonical PoP challenge:
   $$\text{PoP Payload} = \text{SHA-256}(\text{"randbotd\_v1\_offer\_pop\_domain:"} \parallel \text{ca\_id} \parallel \text{offer\_id} \parallel \text{new\_public\_key} \parallel \text{timestamp})$$
   - Verified via `verify_signature_by_algorithm(key_algorithm, new_public_key, payload, proof_of_possession)`.
2. **Old Key Revocation Signature (Optional)**:
   - If the old key is still accessible and uncorrupted, it can emit a revocation signature acknowledging the transition.

### 3.2 Canonical Proof ID & Node Signature

The proof identifier `proof_id` is derived deterministically:
$$\text{proof\_id} = \text{SHA-256}(\text{"randbotd\_v1\_key\_rotation\_proof:"} \parallel \text{ca\_id} \parallel \text{rotation\_seq} \parallel \text{prev\_rotation\_hash} \parallel \text{timestamp} \parallel \text{reason} \parallel \text{rotations...})$$

The entire proof is signed with the CA owner's Ed25519 node signing key:
$$\text{ca\_signature} = \text{Ed25519Sign}(\text{NodeSecretKey}, \text{proof\_id})$$

---

## 4. Anti-Solipsism & Swarm Validation Pipeline

Every peer node independently validates incoming `PAYLOAD_TYPE_KEY_ROTATION` gossip packets:

1. **Owner Binding Verification**:
   The verifying node confirms that `compute_ca_id(ca.subject.common_name, msg.originator_pubkey) == ca.ca_id`. Unauthorized third-party nodes cannot emit rotation proofs for foreign CAs.
2. **Sequential Continuity Check**:
   - For genesis rotation (`rotation_seq = 1`): `prev_rotation_hash == [0; 32]`.
   - For subsequent rotations: `rotation_seq == prev.rotation_seq + 1` and `prev_rotation_hash == prev.proof_id`.
   - `timestamp >= prev.timestamp` (strictly monotonic).
3. **Proof-of-Possession Verification**:
   Every rotated offer item must verify against its declared `key_algorithm` and `new_public_key`.
4. **State Application**:
   - Ingested into the `key_rotations.json` subtable and immutable `event_log.jsonl`.
   - Updates `offer.public_key` in `ca_offers.json` and updates `ca.current_catalog_hash`.
   - If `can_reset_distrust(all_active_offer_ids)` is satisfied: clears standing distrust strikes to 0.
