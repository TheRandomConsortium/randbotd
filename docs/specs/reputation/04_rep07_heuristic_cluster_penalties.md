# Specification: REP-07 Heuristic Cluster Ponderation Penalties

**Status:** Draft / Proposed  
**Roadmap Reference:** `REP-07` (Heuristic Cluster Ponderation Penalties)  
**Related Specifications:** `REP-01` (PoW Challenges), `REP-02` (Dynamic Voting), `REP-03` (Behavioral Ponderation Formula), `REP-04` (Lazy Evaluation Engine)

---

## 1. Executive Summary & Problem Formulation

In a decentralized Web-of-Trust (WoT), malicious actors rarely attack in isolation. Instead, they organize into **collusion rings** or deploy **Sybil bot clusters** that vote in lockstep to:
1. Artificially inflate trust ratings of fraudulent Certificate Authorities (CAs) or phishing domains.
2. Review-bomb legitimate competitor domains into untrusted territory.

Under `REP-03` and `REP-04`, an individual node $u$ that engages in anomalous voting (e.g., rapid flips, high Herfindahl-Hirschman domain concentration, bullshit gossip emissions, or voting against established consensus) is penalized by demoting its local behavioral ponderation score $P(u) \in [0, 100]$.

However, without **Cluster Penalties (`REP-07`)**, a Sybil operator can sacrifice one disposable node while other closely aligned nodes in the ring retain unblemished ponderation weights.

`REP-07` solves this by introducing **Heuristic Cluster Propagation**:
- When node $u$'s vote demotes or promotes its own reputation, nodes **heuristically clustered / closely aligned** with $u$ dynamically share in that penalty/adjustment.
- To maintain real-time daemon responsiveness, this propagation must run **non-blocking and parallel** without degrading the primary vote ingestion write path.
- To prevent out-of-order race conditions and collusive timing attacks, background updates are managed via a **strict FIFO queue worker**.
- To avoid combinatorial $O(V^2 \cdot D)$ double-loops over JSON files, the cluster engine uses an **in-memory Inverted Postings Index** with **Probabilistic Co-Occurrence Sampling** and **Bayesian Shrinkage**.

---

## 2. Why Jaccard Index Fails for Collusion Rings (The Set-Asymmetry Problem)

A classic approach to set similarity is the Jaccard Index:
$$J(A, B) = \frac{|A \cap B|}{|A \cup B|}$$

While mathematically simple, Jaccard is **overly rigid and unsuited for behavioral clustering** due to severe set-size asymmetry:
1. **Asymmetric Sybil Shadows**: Suppose Node $A$ is a focused Sybil puppet that voted on 15 targeted domains. Node $B$ is a master account that voted on those exact same 15 domains identically, but has also voted on 85 other unrelated domains.
   - Directional alignment on shared domains: **$100\%$ identical**.
   - Jaccard similarity: $J(A, B) = \frac{15}{15 + 85} = 0.15$ (disqualified by Jaccard).
2. **False Negatives**: Jaccard penalizes Node $B$ for being active elsewhere, allowing sophisticated Sybil rings with "camouflaged" background activity to evade detection.

`REP-07` instead uses **Probabilistic Directional Agreement over Overlapping Votes**, tempered by **Empirical Bayesian Shrinkage**. This evaluates whether two nodes behave similarly when their voting paths cross, regardless of total asymmetric set size.

---

## 3. Architecture: Decoupled Two-Stage Write Path & FIFO Worker

```
  [Incoming Monotonic Vote on Domain d from Voter u]
                          │
                          ▼
            ┌────────────────────────────┐
            │       First Write          │ (Fast & Synchronous)
            │   db.insert_vote(record)   │
            └─────────────┬──────────────┘
                          │
                          ▼
            ┌────────────────────────────┐
            │ Local Self-Ponderation     │ (Synchronous REP-04)
            │ Compute P(u) & Update Profile
            └─────────────┬──────────────┘
                          │
                          │ non-blocking try_send(ClusterJob)
                          ▼
            ┌────────────────────────────┐
            │     FIFO MPSC Channel      │ (Bounded Toko MPSC)
            └─────────────┬──────────────┘
                          │
                          │ strictly ordered events
                          ▼
═════════════════════════════════════════════════════════════════════════
  [Background Asynchronous Worker: Second Write]
                          │
                          ▼
            ┌────────────────────────────┐
            │   Inverted Index Lookup    │ Candidates V_d = Postings[d]
            │   (Exclude Unrelated Nodes)│ Ω(1) best case, O(k_d) avg
            └─────────────┬──────────────┘
                          │
                          ▼
            ┌────────────────────────────┐
            │ Stratified Sample (≤ 64)   │ O(min(N_u, N_v, 64)) = O(1)
            │ & Bayesian Shrinkage Sim   │
            └─────────────┬──────────────┘
                          │
                          ▼
            ┌────────────────────────────┐
            │  Filter Sim(u, v) ≥ θ_clust│
            │ Apply Damped Penalty       │ Δ_cluster(v) = γ · Sim(u, v) · Δ_demotion(u)
            │ Update Peer Profiles       │
            └────────────────────────────┘
```

### 3.1. First Write (Critical Synchronous Path)
1. Monotonic hash chain validation, PoW puzzle verification, and persistence to `vote_store`.
2. Compute $u$'s own ponderation $P(u)$ via `REP-04`.
3. If $P(u)$ undergoes a significant delta ($|\Delta P(u)| \ge \delta_{\text{trigger}}$, e.g. $\ge 5$ points demotion), push `ClusterJob { voter: u, domain: d, old_score, new_score, timestamp }` into a bounded `tokio::sync::mpsc::channel`.
4. Return immediate success to caller (IPC or P2P gossip peer).

### 3.2. Second Write (Sequential Background FIFO Actor)
1. A single dedicated asynchronous task consumes from the `mpsc` queue in strict FIFO order.
2. **Order Integrity Guarantee**: If Node $A$ emits Vote 1 and Vote 2 in sequence, the worker guarantees Job 1 is fully evaluated before Job 2 begins.
3. This completely prevents out-of-order race conditions, memory stomping, and adversarial timing collusion.

---

## 4. Mathematical Formulation

### 4.1. Inverted Postings Index
The database maintains an in-memory inverted index mapping domains to active voter decisions:
$$\mathcal{I}: d \mapsto \{ (v, \text{action}_v) \mid v \in \mathcal{V}_{\text{active}}(d) \}$$

When node $u$ votes on domain $d$, the candidate peers $\mathcal{C}_{\text{candidates}}$ are strictly:
$$\mathcal{C}_{\text{candidates}} = \{ v \in \mathcal{V}_{\text{active}}(d) \setminus \{u\} \}$$

Peers that have never voted on domain $d$ are **never visited**, reducing candidate search from $O(N_{\text{total\_peers}})$ to $O(k_d)$ where $k_d = |\mathcal{V}_{\text{active}}(d)| \ll N$.

### 4.2. Stratified Representative Sampling
Let $\mathcal{D}_{u \cap v}$ be the intersection of active domains voted on by both $u$ and $v$.
* If $|\mathcal{D}_{u \cap v}| \le M_{\text{sample}}$ (with $M_{\text{sample}} = 64$), use all overlapping domains $\mathcal{S} = \mathcal{D}_{u \cap v}$.
* If $|\mathcal{D}_{u \cap v}| > M_{\text{sample}}$, draw a stratified sample $\mathcal{S}$ of size 64:
  - 32 most recent co-voted domains (capturing current behavior).
  - 32 uniformly sampled historical co-voted domains (capturing long-term alignment).

By Hoeffding's Inequality, with sample size $n = 64$, the sample agreement $\hat{p}$ satisfies:
$$\mathbb{P}(|\hat{p} - p| \ge 0.15) \le 2e^{-2 \times 64 \times (0.15)^2} \approx 0.055$$
yielding $> 94.5\%$ statistical confidence within $\pm 0.15$ tolerance.

### 4.3. Directional Agreement
For each domain $d \in \mathcal{S}$, compare the active vote actions of $u$ and $v$:
$$\text{match}(u, v, d) = \begin{cases} 
1 & \text{if } \text{action}_u(d) == \text{action}_v(d) \\
0 & \text{if } \text{action}_u(d) \neq \text{action}_v(d)
\end{cases}$$

$$\text{Agreement}(u, v) = \frac{1}{|\mathcal{S}|} \sum_{d \in \mathcal{S}} \text{match}(u, v, d)$$

### 4.4. Empirical Bayesian Shrinkage (Statistical Significance Gate)
To prevent small-sample noise from triggering false-positive cluster penalties, the raw agreement is scaled by a shrinkage factor:
$$\text{Weight}_{\text{signif}}(k) = \frac{k}{k + k_0} \quad (\text{default } k_0 = 5.0)$$

$$\text{Sim}(u, v) = \begin{cases}
0.0 & \text{if } |\mathcal{S}| < K_{\text{min}} \quad (K_{\text{min}} = 3) \\
\text{Agreement}(u, v) \times \left( \frac{|\mathcal{S}|}{|\mathcal{S}| + k_0} \right) & \text{if } |\mathcal{S}| \ge K_{\text{min}}
\end{cases}$$

- **$k = 1$ domain overlap**: Below $K_{\text{min}} \implies \text{Sim} = 0.0$.
- **$k = 5$ overlapping domains with 100% agreement**: $\text{Sim} = 1.0 \times \frac{5}{10} = 0.50$ (below cluster threshold $\theta = 0.70$).
- **$k = 20$ overlapping domains with 95% agreement**: $\text{Sim} = 0.95 \times \frac{20}{25} = 0.76$ (qualifies as a cluster peer).

### 4.5. Damped Cluster Penalty Propagation
Two nodes belong to the same heuristic cluster if:
$$\text{Sim}(u, v) \ge \theta_{\text{cluster}} \quad (\text{default } \theta_{\text{cluster}} = 0.70)$$

When node $u$ receives a demotion of magnitude $\Delta_{\text{demotion}}(u) = \max(0, P_{\text{old}}(u) - P_{\text{new}}(u))$:
Every peer $v \in \mathcal{C}(u)$ receives a **guilt-by-association cluster penalty**:
$$\text{Pen}_{\text{cluster}}(v) = \text{round}\Big( \gamma \cdot \text{Sim}(u, v) \cdot \Delta_{\text{demotion}}(u) \Big)$$
*(where $\gamma = 0.5$ is the cluster damping factor)*

$$P_{\text{new}}(v) = \max\Big( 0, P(v) - \text{Pen}_{\text{cluster}}(v) \Big)$$

#### Cascading Prevention Rules
1. **1-Hop Bounded Radius**: Cluster propagation updates direct cluster peers $v \in \mathcal{C}(u)$ only. The update to $v$ does NOT re-trigger another recursive cluster event, preventing infinite feedback loops.
2. **Damping Attenuation ($\gamma = 0.5$)**: The penalty strictly attenuates, ensuring secondary cluster members are never penalized more heavily than the primary offender.

---

## 5. Algorithmic Complexity

| Phase | Naive JSON Approach | REP-07 Inverted Index + Sample |
| :--- | :--- | :--- |
| **Candidate Search** | $O(N_{\text{total\_nodes}})$ disk scans | $\Omega(1)$ best-case, $O(k_d)$ in-RAM |
| **Similarity Evaluation** | $O(D_{\text{total}})$ full JSON diff | $O(\min(N_u, N_v, 64)) = \mathbf{O(1)}$ |
| **Total Event Runtime** | $\Theta(N \cdot D)$ (seconds) | $\mathbf{O(k_d)}$ ($\approx 10 - 200 \ \mu\text{s}$) |
| **Write Path Latency** | Blocks caller | **$\approx 0 \ \mu\text{s}$ (non-blocking channel send)** |

---

## 6. Auditability & Verifiable Cluster Breakdown

When a cluster penalty is applied to peer $v$, the engine logs a structured breakdown:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterPenaltyBreakdown {
    pub target_peer_hex: String,
    pub trigger_peer_hex: String,
    pub co_voted_domains_count: usize,
    pub sample_size: usize,
    pub raw_agreement: f64,
    pub significance_weight: f64,
    pub final_similarity: f64,
    pub trigger_demotion: u32,
    pub damping_factor: f64,
    pub cluster_penalty_applied: u32,
    pub prior_ponderation: u32,
    pub post_ponderation: u32,
    pub timestamp: u64,
}
```

---

## 7. Security Guarantees & Sybil Defenses

1. **Sybil Cluster Neutralization**: When a Sybil ring review-bombs a domain, the first puppet node penalized pulls down the ponderation weights of all correlated ring members.
2. **Resistance to Infiltration Attacks**: An honest high-reputation node cannot be easily framed or dragged down by a malicious node intentionally copying its votes:
   - High-reputation nodes have broad, mature vote distribution ($k \gg 64$).
   - A disposable attacker copying a few votes has $k < k_0$, dampening similarity below $\theta_{\text{cluster}}$.
   - High affinity with other honest peers ($\Delta_{\text{high}}$) provides positive counter-weight in `REP-03`.
