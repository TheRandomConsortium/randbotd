# ⚖️ Phase 10 (`SWARM-01`): Custodian Swarm Free-Market Dynamics & Dynamic Under-Bidding Engine
### *Part 5: Competitive Swarm Allocation, Under-Bidding Displacement & Anti-Calcification Invariants*

---

## 1. Executive Summary & Problem Formulation

In a decentralized Certificate Authority, operational load and signing delegation are distributed across a swarm of custodian workers (`CA-11`). To protect CA nodes from resource exhaustion, local blind acceptance policies specify a capacity ceiling: `target_swarm_size` (e.g., $N = 5$ workers).

### The First-Mover Monopoly Hazard (Swarm Calcification)
Under a naive capacity enforcement model:
1. The first $N$ workers to petition the CA claim all available slots.
2. Even if these initial workers demand the maximum allowable revenue share (e.g., 25% or 30%), the swarm reaches full capacity (`active_custodians.len() >= target_swarm_size`).
3. Subsequent petitions from higher-performing, lower-cost workers (e.g., proposing 10% or 15% revenue share) are **silently dropped**, regardless of their economic superiority.
4. Result: Early participants lock in high fee margins, causing economic calcification and denying the CA the benefits of a competitive open market.

---

## 2. Free-Market Under-Bidding & Displacement Dynamic

To eliminate first-mover monopolies and establish continuous downward pressure on delegation cuts, `randbotd` implements an automated **Free-Market Under-Bidding & Displacement Engine**.

```
+--------------------------------------------------------------------------------------------------+
|                            INCOMING WORKER CONTRACT: W_new (work_share_pct)                      |
+--------------------------------------------------------------------------------------------------+
                                                 |
                                                 v
                               +-----------------------------------+
                               | active_custodians < target_size?  |
                               +-----------------------------------+
                                       /                   \
                               (YES)  /                     \  (NO - At Capacity)
                                     v                       v
                      +----------------------+      +-----------------------------------------+
                      | Standard Onboarding  |      | Find worker with MAX current percentage |
                      | Challenge (Step 2-4) |      | W_max = argmax(w.work_share_pct)        |
                      +----------------------+      +-----------------------------------------+
                                                                         |
                                                                         v
                                                    +-----------------------------------------+
                                                    | Is W_new.work_share_pct < W_max.pct?    |
                                                    +-----------------------------------------+
                                                           /                           \
                                                   (YES)  /                             \  (NO)
                                                         v                               v
                                          +------------------------------+     +--------------------+
                                          | Stage W_new for Challenge    |     | Strict Silent Drop |
                                          | Keep W_max active for now    |     | (Zero Response)    |
                                          +------------------------------+     +--------------------+
                                                         |
                                                         v
                                          +------------------------------+
                                          | W_new completes Step 3 & 4   |
                                          | (TCP cert fetch + verify)    |
                                          +------------------------------+
                                                         |
                                                         v
                                          +------------------------------+
                                          | ATOMIC REPLACEMENT SWAP:     |
                                          | 1. Evict W_max from swarm    |
                                          | 2. Activate W_new in slot    |
                                          | 3. Broadcast Activation      |
                                          +------------------------------+
```

---

## 3. Algorithmic State Transitions

### Step 1: Pre-Qualification & Capacity Evaluation
When an incoming `CustodianContract` arrives at the CA:
1. Verify signature, validity window ($\text{valid\_until} - \text{created\_at} \ge \text{min\_ttl\_seconds}$), and worker CA network capability coverage.
2. If `contract.work_share_pct > policy.max_work_share_pct`: **Silently drop**.
3. Evaluate capacity:
   - **Case A: `active_custodians.len() < policy.target_swarm_size`**:
     - The CA issues a `CustodianDelegationRequest` challenge as normal.
   - **Case B: `active_custodians.len() >= policy.target_swarm_size`**:
     - Query active records in `custodians.json`.
     - Identify the highest-percentage active worker:
       $$W_{\text{max}} = \arg\max_{w \in \text{Swarm}} (w.\text{work\_share\_pct})$$
     - Compare proposed cuts:
       - If $W_{\text{new}}.\text{work\_share\_pct} < W_{\text{max}}.\text{work\_share\_pct}$:
         - **Market displacement triggered**: $W_{\text{new}}$ is under-bidding the most expensive incumbent.
         - Stage the petition: map $W_{\text{new}} \rightarrow W_{\text{max}}$ in `pending_displacements`.
         - Issue Step 2 challenge to $W_{\text{new}}$.
       - If $W_{\text{new}}.\text{work\_share\_pct} \ge W_{\text{max}}.\text{work\_share\_pct}$:
         - **Silently drop**: $W_{\text{new}}$ offers no economic benefit over incumbents.

### Step 2: Tie-Breaking Invariant for Identical Maximums
If multiple active incumbents share the identical maximum work-share percentage ($w_i.\text{work\_share\_pct} = w_j.\text{work\_share\_pct}$):
1. **Earliest Expiration First**: Evict the worker whose `valid_until` expires soonest (minimizing contract breach).
2. **Oldest Activation First**: If expiration timestamps are equivalent, evict the worker who has held the slot the longest (`activated_at` ascending), granting fresher market applicants operational opportunity.

### Step 3: Zero-Disruption Staged Eviction
To prevent Denial-of-Service or temporary capacity reduction caused by unverified or flaky under-bidders:
- **No Premature Eviction**: $W_{\text{max}}$ remains an active, fully authorized custodian while $W_{\text{new}}$ solves the challenge and uploads the mock capability certificate.
- **Atomic Replacement Commit**: Only when $W_{\text{new}}$ successfully delivers its verified X.509 DER certificate over TCP and passes all consensus checks does the CA execute:
  1. Remove $W_{\text{max}}$ from `custodians.json`.
  2. Insert $W_{\text{new}}$ into `custodians.json`.
  3. Broadcast `PAYLOAD_TYPE_SWARM_ACTIVATION` for $W_{\text{new}}$.

If $W_{\text{new}}$ times out, fails TCP transfer, or provides an invalid certificate, $W_{\text{new}}$ is discarded and $W_{\text{max}}$ retains its slot without interruption.

---

## 4. Game-Theoretic Invariants & Attack Resistance

| Attack Vector / Failure Mode | Threat Profile | Defense & Mathematical Invariant |
| :--- | :--- | :--- |
| **Monopolistic Fee Locking** | Early cartel fills all swarm slots at 30% revenue share. | **Under-bidding displacement**: Any entrant offering 20% or 10% automatically displaces the highest cartel member. |
| **Troll Displacement DoS** | Malicious node proposes 1% fee with intent to fail challenge, disrupting capacity. | **Staged atomic replacement**: The incumbent is never evicted until the challenger has fully proved DER capabilities and completed TCP handshake. |
| **Micro-Churn / Penny-Jumping** | Attacker proposes 24.99% to displace 25.00%, creating high database churn. | Optional CA operator policy parameter `min_displacement_delta_pct` (e.g. minimum 2% or 5% discount required to trigger eviction). |
| **Free-Market Downward Spiral** | Fee rates compete down to zero, risking custodian unprofitability. | Workers self-select their own floor via `work_share_pct` in their signed contracts based on hardware and bandwidth amortization. |

---

## 5. Integration with CA Command Center Dashboard (`CA-06`)

During operator oversight in the Command Center (`CA-06`):
- **Swarm Bid Curve**: Real-time visualization of active custodian revenue-share percentages vs. pending under-bids.
- **Displacement History**: Audit log of displaced incumbents, replacement candidates, and realized fee margin savings.
- **Policy Controls**: Dynamic configuration of `target_swarm_size`, `max_work_share_pct`, and `min_displacement_delta_pct` via local IPC.
