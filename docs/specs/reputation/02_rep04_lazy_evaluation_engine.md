# Specification: REP-04 Lazy Evaluation Engine & Dynamic Delta

**Status:** Accepted / Active  
**Roadmap Reference:** `REP-04` (Lazy Evaluation Engine)  
**Related Specifications:** `REP-01` (PoW Challenges), `REP-02` (Dynamic Voting), `REP-03` (Behavioral Ponderation), `ACME-02` (50% Baseline), `ACME-04` (Dynamic Delta)

---

## 1. Executive Summary & Problem Formulation

Decentralized Web-of-Trust (WoT) systems frequently suffer from combinatorial recalculation explosions ($O(N^M)$ or $O(V^2 \cdot D)$) if reputation scores and peer affinities are evaluated globally and recursively upon every domain query.

In `randbotd`, voter ponderation $P(u) \in [0, 100]$ (`REP-03`) depends on:
1. Multi-domain consensus alignment $\Delta_{\text{cons}}(u)$.
2. Correlation with high-reputation peers $\Delta_{\text{high}}(u)$ ($P_0 \ge 70$).
3. Agreement with low-reputation peers $\Delta_{\text{low}}(u)$ ($P_0 \le 30$).

If querying a domain's trust score naively recomputed all voter ponderations and peer clusters on-the-fly, execution time would explode exponentially.

`REP-04` solves this via a **Write/Read Split Architecture**:
- **Write Path (Vote Ingestion)**: When a node casts or gossips a vote, domain consensus state is incrementally updated and the voter's ponderation $P(u)$ is computed using cached metrics and stored in their profile (`PeerEntry.ponderation_score`).
- **Read Path (Lazy Evaluation)**: When a domain is queried or evaluated for fair-band ACME matching, trust score aggregation is strictly **$O(n)$** over the active votes of that single domain:
  $$\text{TrustScore}(d) = \frac{\sum_{i=1}^n \text{weight}(v_i) \cdot P(u_i)}{\sum_{i=1}^n P(u_i)} \times 100.0$$
- **Dynamic Delta ($\Delta$) Rescaling**: Computes the matching tolerance window $[\text{TrustScore} \pm \Delta]$, where $\Delta$ naturally starts at $\pm 50.0\%$ (neutral) and decays logarithmically as domain votes accumulate, while automatically rescaling (widening) when active network nodes $N_{\text{active\_nodes}}$ expand.

---

## 2. Write/Read Split & Caching Architecture

```
                    ┌────────────────────────────┐
                    │      Gossip / IPC Vote     │
                    └─────────────┬──────────────┘
                                  │
                                  ▼
                    ┌────────────────────────────┐
                    │  db.insert_vote(record)    │
                    └──────┬──────────────┬──────┘
                           │              │
       [Write Path 1]      ▼              ▼      [Write Path 2]
    ┌───────────────────────────┐   ┌───────────────────────────┐
    │ Update Domain Consensus   │   │ Update Voter Profile      │
    │ Cache: direction & σ(d)   │   │ P(u) in PeerEntry         │
    └───────────────────────────┘   └───────────────────────────┘
                                                  │
 ═════════════════════════════════════════════════╪═══════════════════════
 [Read Path: On-Demand Lazy Evaluation]           ▼
    ┌───────────────────────────────────────────────────────────┐
    │ evaluate_domain_trust(domain, active_votes, profiles, N)  │
    │  - Retrieve cached P(u_i) in O(1) per active vote         │
    │  - Compute weighted TrustScore(d) in O(n)                 │
    │  - Compute Dynamic Delta Δ(d, N_nodes) in O(1)            │
    └───────────────────────────────────────────────────────────┘
```

---

## 3. Mathematical Formulation

### 3.1. Domain Consensus Cache (`DomainConsensus`)
For every domain $d$ with active votes, consensus state is maintained:
- $W_{\text{TW}}(d) = \sum_{v \in \text{TW}} P(v)$
- $W_{\text{UTW}}(d) = \sum_{v \in \text{UTW}} P(v)$
- Consensus Direction $D(d)$:
  $$D(d) = \begin{cases}
  \text{TW}, & \text{if } W_{\text{TW}} > W_{\text{UTW}} \\
  \text{UTW}, & \text{if } W_{\text{UTW}} > W_{\text{TW}} \\
  \text{Undecided}, & \text{if } W_{\text{TW}} = W_{\text{UTW}} \text{ or } n = 0
  \end{cases}$$
- Confidence $\sigma(d) \in [0.0, 1.0]$:
  $$\sigma(d) = \frac{|W_{\text{TW}} - W_{\text{UTW}}|}{\max(1.0, W_{\text{TW}} + W_{\text{UTW}})}$$

### 3.2. Voter Ponderation Update
When calculating voter $u$'s score, consensus alignment iterates only through the domains $u$ has voted on:
$$\text{Align}_u = \frac{\sum_{d \in \mathcal{D}_u} \text{match}_u(d) \cdot \sigma(d)}{\max(1, |\mathcal{D}_u^{\text{consensus}}|)}$$
Because $\sigma(d)$ and $D(d)$ are pre-cached on each domain, calculating $\text{Align}_u$ requires only $O(|\mathcal{D}_u|)$ operations instead of scanning all peers' votes across the network.

### 3.3. Lazy Domain Trust Evaluation
When domain $d$ is queried:
1. If active votes $n = 0$:
   $$\text{TrustScore}(d) = 50.0\% \quad (\text{Neutral Baseline per ACME-02})$$
   $$\Delta(d) = 50.0\% \implies \text{Tolerance Window: } [0.0\%, 100.0\%]$$
2. If active votes $n > 0$:
   $$\text{TrustScore}(d) = \frac{W_{\text{TW}}(d)}{W_{\text{TW}}(d) + W_{\text{UTW}}(d)} \times 100.0$$
   (If total weight is 0, defaults to 50.0%).

### 3.4. Dynamic Delta ($\Delta$) Rescaling Formula
Matching tolerance $\Delta \in [0.0, 50.0\%]$ is governed by:
$$\Delta(d) = 50.0 \times \left(1.0 - \min\left(1.0, \frac{\ln(1 + n)}{\ln(1 + \max(1, N_{\text{active\_nodes}}))}\right)\right)$$
- **Zero Votes**: $n = 0 \implies \Delta = 50.0\%$.
- **Maturity**: When $n \ge N_{\text{active\_nodes}}$, $\Delta \to 0\%$.
- **Network Scaling**: As $N_{\text{active\_nodes}}$ expands, $\ln(1 + N_{\text{active\_nodes}})$ grows, naturally widening $\Delta$ for domains with fewer votes until more peers confirm the rating.

---

## 4. Complexity Analysis

| Operation | Naive Recursive WoT | REP-04 Split & Cache Architecture |
| :--- | :--- | :--- |
| **Domain Trust Query** | $O(N^M)$ (recursive peer explosion) | **$O(n)$** ($n = \text{votes on domain}$) |
| **Dynamic Delta $\Delta$** | $O(N_{\text{voters}} \cdot D)$ | **$O(1)$** |
| **Consensus Alignment** | $O(D_u \cdot N_{\text{voters}})$ | **$O(D_u)$** (reads cached $\sigma(d)$) |
| **Peer Affinity $\Delta_{\text{high}}, \Delta_{\text{low}}$** | Infinite loop or multi-pass matrix solve | **$O(P_{\text{cached}})$** (snapshot decoupling) |
