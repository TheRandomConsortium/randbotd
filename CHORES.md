# 🛠️ `randbotd` Chore List & Technical Debt

This document tracks minor maintenance tasks, refactoring needs, infrastructure improvements, and technical debt accumulated during the development of `randbotd`.

---

## 🧹 Active Chores & Technical Debt

*No active chores or technical debt currently logged.*

---

## ✅ Completed Chores

* [x] **`NET-02` Gossip Router Seen Cache Eviction**: Implemented timestamp-bounded eviction for `GossipRouter.seen_cache` (`HashMap<[u8; 32], u64>`) to purge expired message IDs older than 1 hour (3600s) during periodic keepalive cycles.
* [x] **`SEC-01` Mnemonic Log Leak Prevention**: Prevented recovery phrase leakage into systemd `journalctl` logs. Written generated phrases to RAM-backed file (`/dev/shm/randbotd_mnemonic_<PID>.txt`) with strict `0600` permissions.
* [x] **`SEC-02` Shell History Protection Notice**: Updated CLI error messages and debian package `postinst` script to instruct operators to set `set +o history` before entering passphrases.
