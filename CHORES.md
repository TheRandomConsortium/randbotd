# 🛠️ `randbotd` Chore List & Technical Debt

This document tracks minor maintenance tasks, refactoring needs, infrastructure improvements, and technical debt accumulated during the development of `randbotd`.

---

## 🧹 Active Chores & Technical Debt

* [ ] **`NET-02` Gossip Router Seen Cache Eviction**: Implement timestamp-bounded eviction for `GossipRouter.seen_cache` (`HashMap<[u8; 32], u64>`) to purge expired message IDs older than 1 hour, preventing unbounded memory growth in long-running daemons.

---

## ✅ Completed Chores

*No completed chores yet.*
