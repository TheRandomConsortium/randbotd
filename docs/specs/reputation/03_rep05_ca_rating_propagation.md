# Specification: REP-05 CA Rating Propagation Engine & Bi-Directional Image Cleaning

**Status:** Accepted / Active  
**Roadmap Reference:** `REP-05` (CA Rating Propagation Engine), `REP-06` (Bi-Directional Image Cleaning)  
**Related Specifications:** `REP-03` (Behavioral Ponderation), `REP-04` (Lazy Evaluation Engine), `ACME-02` (50% Baseline), `ACME-04` (Dynamic Delta), `CA-07` (Domain Purge)

---

## 1. Executive Summary & Problem Formulation

In a decentralized public key infrastructure (P2P WoT PKI), evaluating the trustworthiness of a Certificate Authority (CA) cannot rely on static pre-installed trust roots or central vetting. Instead, a CA's public reputation must derive dynamically and objectively from the aggregate consensus of all domains it has issued.

In `randbotd`, a CA issues leaf certificates for multiple domains $\mathcal{D}(\text{CA}) = \{d_1, d_2, \dots, d_m\}$. Each domain accumulates peer trust votes governed by `REP-02`, behavioral ponderations $P(u) \in [0, 100]$ under `REP-03`, and lazy evaluation under `REP-04`.

### 1.1 The Ground-Truth Invariant vs. Caching Drift
A naive caching mechanism that stores pre-calculated domain scores and invalidates them only upon direct domain votes or node activity timestamps introduces critical failure modes:
1. **Timestamp Check Cost**: Verifying if any historical voter on $m$ domains interacted with the network requires $O(m \cdot n)$ comparisons—matching the asymptotic cost of evaluating the formula directly.
2. **Permanent Cache Thrashing**: In an active P2P network, nodes emit votes continuously across different domains. Timestamp-based invalidation would invalidate domain caches constantly, resulting in cache hit rates approaching 0% and doubling CPU overhead.
3. **Statistical Artifacts**: If domain trust scores are cached and decoupled from voter behavior, votes cast by a peer elsewhere alter their behavioral ponderation $P(u)$, causing cached domain and CA scores to drift into statistical artifacts unaligned with real network consensus.

`REP-05` adheres strictly to **Ground-Truth On-Demand Lazy Evaluation (Option A)**:
- Whenever a CA rating is queried, domain evaluations are evaluated in real-time using pre-cached peer ponderation weights from `Phonebook` ($O(1)$ lookup per vote).
- The computational overhead in Rust across thousands of votes is strictly linear ($O(N_{\text{total\_ca\_votes}})$), taking only tens of microseconds without caching desynchronization bugs.

---

## 2. Mathematical Formulation

### 2.1 Domain Discovery & Exclusion Set ($\mathcal{D}(\text{CA})$)
Given a target CA with identifier `ca_id`:
1. **Certificate Chain Traversal**: All certificate chains in `Database::list_cert_chains()` issued under this CA are identified.
2. **Domain Extraction**: Fully-qualified domain names are extracted from leaf certificates ($d \in \text{SANs} \cup \{\text{CN}\}$).
3. **Revocation & Purge Filter (`REP-06` / `CA-07`)**:
   - Any certificate marked revoked in the CA's Certificate Revocation List (CRL) is excluded.
   - Any domain subject to an active, unexpired `DomainPurgeRecord` (`CA-07`) issued by this CA is excluded.
4. The remaining distinct domain set constitutes the active issued domains:
   $$\mathcal{D}(\text{CA}) = \{d_1, d_2, \dots, d_m\}$$

### 2.2 On-Demand Domain Trust Evaluation
For each domain $d_j \in \mathcal{D}(\text{CA})$, trust is evaluated via `REP-04`:
- $T(d_j) \in [0.0, 100.0]$: Aggregated domain trust score.
- $W(d_j) = W_{\text{TW}}(d_j) + W_{\text{UTW}}(d_j)$: Total weighted voter ponderation sum for $d_j$.
- $n_j$: Number of active votes cast for $d_j$.

### 2.3 CA Public Rating Weighted Average
A CA's public rating is the weighted average of its active domains weighted by their total community consensus ponderation $W(d_j)$:

$$\text{Rating}(\text{CA}) = \begin{cases}
50.0\%, & \text{if } \sum_{j=1}^m W(d_j) = 0 \text{ or } m = 0 \quad (\text{Neutral Baseline per ACME-02}) \\
\dfrac{\sum_{j=1}^m W(d_j) \cdot T(d_j)}{\sum_{j=1}^m W(d_j)}, & \text{otherwise}
\end{cases}$$

Weighting by $W(d_j)$ ensures that mature domains with deep community consensus have proportional influence, preventing Sybil dilution via empty or low-stake domains.

### 2.4 Dynamic CA Tolerance Window ($\pm \Delta_{\text{CA}}$)
In accordance with `ACME-04` and `REP-04`, the CA's rating carries a dynamic confidence tolerance window derived logarithmically from total network vote participation:
$$N_{\text{total\_ca\_votes}} = \sum_{j=1}^m n_j$$

$$\Delta_{\text{CA}} = 50.0 \times \left(1.0 - \min\left(1.0, \frac{\ln(1 + N_{\text{total\_ca\_votes}})}{\ln(1 + \max(1, N_{\text{active\_nodes}}))}\right)\right)$$

Confidence bounds:
$$\text{LowerBound}(\text{CA}) = \max(0.0, \text{Rating}(\text{CA}) - \Delta_{\text{CA}})$$
$$\text{UpperBound}(\text{CA}) = \min(100.0, \text{Rating}(\text{CA}) + \Delta_{\text{CA}})$$

- **Zero Votes**: A new CA with no votes on its issued domains has $\text{Rating} = 50.0\%$ and $\Delta_{\text{CA}} = \pm 50.0\%$, yielding full neutral tolerance $[0.0\%, 100.0\%]$.
- **Maturity**: As votes accumulate across its domains towards $N_{\text{active\_nodes}}$, $\Delta_{\text{CA}} \to 0.0\%$, solidifying its public score.

---

## 3. Bi-Directional Image Cleaning (`REP-06`)

`REP-06` establishes symmetric mechanisms for reputation recovery:
1. **Domain Strike Recovery**: Honest domains targeted by Sybil review-bomb bursts recover via `REP-03`/`REP-04` burst penalties ($\Delta_{\text{burst}}$) and logarithmic PoW flip escalations ($P_{\text{flip}}$).
2. **CA Image Restoration via Domain Purge (`CA-07`)**:
   - If an issued domain turns rogue (malware, phishing, UTW flood), it degrades the parent CA's rating.
   - When the CA operator executes a cryptographic `DomainPurgeRecord` (`CA-07`), that domain is immediately excluded from $\mathcal{D}(\text{CA})$.
   - On the next real-time on-demand evaluation, the CA's public rating instantly recovers without historical lag or manual administrative intervention.

---

## 4. Complexity Analysis

| Operation | Naive Matrix / Recursive WoT | Caching with Timestamps | REP-05 On-Demand Direct Engine |
| :--- | :--- | :--- | :--- |
| **CA Rating Evaluation** | $O(N^M)$ | $O(m \cdot n)$ check + $O(m \cdot n)$ compute | **$O(N_{\text{total\_ca\_votes}})$** |
| **Write Path Overhead** | Heavy graph lock | Cascading cache invalidation | **$O(1)$** (zero CA write overhead) |
| **Consistency Guarantee** | Periodic convergence | Stale / Drifted artifacts | **Exact ground-truth real-time** |
| **Execution Latency** | Seconds / Minutes | Milliseconds (thrashing) | **$10 - 40\,\mu\text{s}$** (microseconds in memory) |
