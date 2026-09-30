# Specification: REP-03 Behavioral Score & Weight Ponderation Engine

**Status:** Draft / Accepted  
**Roadmap Reference:** `REP-03` (Behavioral Score & Weight Ponderation)  
**Related Specifications:** `REP-01` (PoW Challenges), `REP-02` (1-Vote-Per-Node Dynamic Voting), `REP-04` (Lazy Evaluation Engine), `REP-07` (Heuristic Cluster Penalties)

---

## 1. Executive Summary & Problem Formulation

In a decentralized Web-of-Trust (WoT) without central authority or financial gatekeepers, transport layer reputation and certificate trust depend entirely on peer voting. However, unweighted 1-node-1-vote systems are inherently vulnerable to:
1. **Sybil Attacks**: An adversary generating thousands of lightweight Ed25519 keypairs to flood votes.
2. **Review-Bombing Rings**: Coordinated bots flipping domain ratings (`TW` $\leftrightarrow$ `UTW`) to extort or de-platform honest domains.
3. **Consensus Hijacking**: Colluding nodes endorsing malicious/phishing infrastructure.
4. **Byzantine Equivocation**: Malicious nodes broadcasting conflicting payloads or broken sequence chains to disrupt anti-entropy synchronization.

`REP-03` introduces the **Behavioral Score & Weight Ponderation Engine**. Every node independently and deterministically computes a behavioral score $P(u) \in [0, 100]$ for any network participant $u$ using purely local, cryptographically signed data replicated via anti-entropy gossip (`event_log` and `vote_store`).

In accordance with the **Lazy Evaluation Architecture (`REP-04`)**, the inputs and mathematical formulation are decoupled from real-time continuous background execution:
- **`REP-03`** defines the **input metrics, data structures, and deterministic mathematical formula**.
- **`REP-04`** executes the calculation **lazily on-demand** when domain/CA trust windows ($\pm \Delta$) or certificate allocations are queried.

---

## 2. Ponderation Input Vectors (`PonderationInputs`)

All inputs are deterministically extracted from the node's local database without external oracles:

```rust
pub struct PonderationInputs {
    /// Ed25519 public key of the evaluated voter node
    pub voter_pubkey: [u8; 32],
    /// Whether this node operates in headless / infrastructure mode (Manifesto §2.IV)
    pub is_headless: bool,
    /// Has the node committed proven Byzantine double-signing (PAYLOAD_TYPE_EQUIVOCATION_PROOF)
    pub is_equivocator: bool,
    /// Active distinct domains voted on by this node within rolling 1-year window
    pub active_votes_count: usize,
    /// Total lifetime monotonic votes emitted by this node
    pub total_votes_emitted: u64,
    /// Total distinct active voting nodes in the local network view
    pub network_active_voters: usize,
    /// Total distinct domains currently voted on across the network
    pub network_active_domains: usize,
    /// Number of ingested bullshit events emitted by this originator
    pub bullshit_events_count: usize,
    /// Number of valid consensus events emitted by this originator
    pub valid_events_count: usize,
    /// Consensus alignment metric in [-1.0, 1.0] across domains with established consensus
    pub consensus_alignment: f64,
    /// Number of anomalous rapid flips on the same domain (delta_t < 300s)
    pub rapid_flips_count: usize,
    /// Number of rapid multi-domain burst clusters emitted in short windows (< 60s)
    pub burst_clusters_count: usize,
    /// Correlation with high-ponderation peers (P0 >= 70) in [-1.0, 1.0]
    pub high_ponderation_affinity: f64,
    /// Agreement with low-ponderation peers (P0 <= 30) in [0.0, 1.0]
    pub low_ponderation_agreement: f64,
    /// Target domain voting concentration (Herfindahl-Hirschman Index in [0.0, 1.0])
    pub target_concentration_hhi: f64,
}
```

---

## 3. The Master Ponderation Formula

For any evaluated node $u$, the ponderation score $P(u) \in [0, 100]$ is governed by:

$$P(u) = \begin{cases}
0, & \text{if } u.\text{is\_headless} = \text{true} \\
0, & \text{if } u.\text{is\_equivocator} = \text{true} \\
\text{clamp}\Big( \text{ROUND}\big( P_{\text{base}} + \Delta_{\text{vol}}(u) - \Delta_{\text{bs}}(u) + \Delta_{\text{cons}}(u) - \Delta_{\text{burst}}(u) + \Delta_{\text{high}}(u) - \Delta_{\text{low}}(u) - \Delta_{\text{conc}}(u) \big), 0, 100 \Big), & \text{otherwise}
\end{cases}$$

### 3.1. Neutral Baseline ($P_{\text{base}} = 50.0$)
In alignment with `ACME-02` (50% neutral baseline with 0 votes), a fresh, well-behaved node starts with a neutral score of **50**.

### 3.2. Vote Volume & Maturity Scaling ($\Delta_{\text{vol}}$)
Logarithmic maturity curve based on active domain votes:
$$\Delta_{\text{vol}}(u) = 15.0 \times \frac{\ln(1 + V_u^{\text{active}})}{\ln(1 + V_{\text{target}})}, \quad V_{\text{target}} = \min(20, \max(5, \lfloor 0.25 \times N_{\text{domains}} \rfloor))$$
- Capped at $+15.0$ points.
- Prevents zero-history Sybil accounts from having mature voting power.

### 3.3. Bullshit Event Penalty ($\Delta_{\text{bs}}$)
Non-monotonic sequences, broken hash links, and invalid signatures recorded on the anti-entropy ledger inflict quadratic and ratio-based penalties:
$$\Delta_{\text{bs}}(u) = \min\left(100.0, 20.0 \times B_u + 40.0 \times \frac{B_u}{B_u + V_u^{\text{valid}} + 1}\right)$$
- 1 bullshit event drops the node by $\approx -25$ points.
- $\ge 4$ bullshit events crush the node's ponderation to **0**.

### 3.4. Closeness to Consensus ($\Delta_{\text{cons}}$)
For each domain $d$ where $u$ voted, the consensus direction $D(d)$ and confidence $\sigma(d)$ among *other* network peers ($k \ge 2$) are evaluated:
$$\sigma(d) = \frac{|TW_{-u}(d) - UTW_{-u}(d)|}{TW_{-u}(d) + UTW_{-u}(d)}$$
$$\text{Align}_u = \frac{\sum_{d} \text{match}_u(d) \cdot \sigma(d)}{\max(1, |\mathcal{D}_u^{\text{consensus}}|)} \in [-1.0, 1.0]$$
$$\Delta_{\text{cons}}(u) = 20.0 \times \text{Align}_u$$
- Voting with established consensus: up to $+20.0$ bonus.
- Contrarian review-bombing of consensus domains: up to $-20.0$ penalty.
- Early votes on fresh domains ($\sigma = 0$ or $k < 2$) carry no penalty or reward.

### 3.5. Burst & Oscillation Penalty ($\Delta_{\text{burst}}$)
Rapid mind-change flips ($\Delta t < 300\text{s}$) or multi-domain flooding bursts ($> 5$ votes in 60s):
$$\Delta_{\text{burst}}(u) = \min\left(40.0, 15.0 \times N_{\text{rapid\_flips}} + 10.0 \times N_{\text{burst\_clusters}}\right)$$
- Neutralizes automated bot oscillations and review-bombing spikes.

### 3.6. Closeness to High Ponderation Nodes ($\Delta_{\text{high}}$)
2-pass decoupled peer correlation:
$$\Delta_{\text{high}}(u) = 15.0 \times \max(0.0, \Gamma_u^{\text{high}})$$
- Agreement with established, high-reputation peers ($P_0 \ge 70$) yields up to $+15.0$ reinforcement.

### 3.7. Closeness to Low Ponderation Nodes ($\Delta_{\text{low}}$)
$$\Delta_{\text{low}}(u) = 15.0 \times \Gamma_u^{\text{low}}$$
- Voting in lockstep with penalized/low-reputation peers ($P_0 \le 30$) penalizes the node by up to $-15.0$ points.
- Breaks Sybil collusion rings (`REP-07` foundation).

### 3.8. Target Concentration / Brigading Penalty ($\Delta_{\text{conc}}$)
Using the Herfindahl-Hirschman Index (HHI) of vote distribution:
$$\text{HHI}_u = \sum_{d} \left(\frac{v_d}{V_u^{\text{total}}}\right)^2$$
If $V_u^{\text{total}} \ge 5$ and $\text{HHI}_u > 0.6$:
$$\Delta_{\text{conc}}(u) = 15.0 \times \frac{\text{HHI}_u - 0.6}{0.4}$$
- Penalizes accounts whose sole activity is brigading a single target domain.

---

## 4. Game-Theoretic Attack Mitigation Guarantees

| Attack Vector | Threat Mechanism | Mathematical Defense in REP-03 |
| :--- | :--- | :--- |
| **Sybil Flood** | Attacker spins up 1,000 new nodes to vote on a domain. | Fresh nodes have $V_u = 1$, 0 consensus track record, and 0 peer affinity; voting weight is minimal ($\approx 50$ baseline without volume or consensus boost). |
| **Review-Bomb Burst** | Attacker rapidly flips votes back and forth to disrupt consensus. | Triggers $\Delta_{\text{burst}}$ (up to $-40$) and logarithmic PoW flip penalty $P_{\text{flip}}$ from `REP-01`. |
| **Collusion Ring** | 50 nodes vote identically to boost a rogue CA or fake domain. | Lack of agreement with high-ponderation nodes ($\Delta_{\text{high}} = 0$) and mutual agreement with low-ponderation peers ($\Delta_{\text{low}}$) pulls the entire cluster down. |
| **Byzantine Desync** | Node broadcasts invalid sequences or double-signs messages. | Bullshit events trigger $\Delta_{\text{bs}}$ (up to $-100$); Equivocation proofs immediately trigger $P(u) = 0$. |
| **Targeted Brigading** | Disposable node created exclusively to bomb one competitor. | High HHI concentration triggers $\Delta_{\text{conc}}$ (up to $-15$). |

---

## 5. Auditability & Explanatory Breakdown (`PonderationBreakdown`)

Every calculation returns a comprehensive breakdown struct, ensuring 100% transparent verification:

```rust
pub struct PonderationBreakdown {
    pub pubkey_hex: String,
    pub base_score: f64,
    pub volume_bonus: f64,
    pub bullshit_penalty: f64,
    pub consensus_alignment_adjustment: f64,
    pub burst_penalty: f64,
    pub high_ponderation_affinity_bonus: f64,
    pub low_ponderation_agreement_penalty: f64,
    pub target_concentration_penalty: f64,
    pub is_headless: bool,
    pub is_equivocator: bool,
    pub final_score: u32,
}
```
