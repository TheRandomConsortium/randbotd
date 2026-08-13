# 🛠️ `randbotd` Chore List & Technical Debt

This document tracks minor maintenance tasks, refactoring needs, infrastructure improvements, and technical debt accumulated during the development of `randbotd`.

---

## 🧹 Active Chores & Technical Debt

*No active chores or technical debt currently logged.*

---

### CA Identity

* [ ] **`CA-ID-01` Bind `ca_id` to Owner Node Pubkey (composite)**: Currently `compute_ca_id` in [`src/crypto/ca.rs`](file:///home/mreugenej7/git/randbotd/src/crypto/ca.rs) is called with `subject.common_name.as_bytes()` in [`src/net/ipc/handler.rs`](file:///home/mreugenej7/git/randbotd/src/net/ipc/handler.rs#L130). Change the derivation to:

  ```
  ca_id = SHA-256("randbotd_v1_ca_identity_domain:" || common_name || ":" || node_pubkey_bytes)
  ```

  Including `common_name` allows a single node to own multiple distinct CAs (e.g. a Root CA and an Intermediate CA, or CAs for different trust domains) without collision. Including `node_pubkey_bytes` cryptographically binds ownership — no other node can claim or modify the CA without controlling the original keypair. A node still only casts one vote in reputation/consensus regardless of how many CAs it operates. Ultra-minor change: update `compute_ca_id` signature and the single call site in `handle_publish_ca`, plus the IPC test fixtures that currently pass bare `b"fake_pubkey"` / `b"test_net_pubkey"` literals.




---

## ✅ Completed Chores

* [x] **`NET-02` Gossip Router Seen Cache Eviction**: Implemented timestamp-bounded eviction for `GossipRouter.seen_cache` (`HashMap<[u8; 32], u64>`) to purge expired message IDs older than 1 hour (3600s) during periodic keepalive cycles.
* [x] **`SEC-01` Mnemonic Log Leak Prevention & Secure Deletion**: Prevented recovery phrase leakage into systemd `journalctl` logs. Written generated phrases to RAM-backed file (`/dev/shm/randbotd_mnemonic_<PID>.txt`) with strict `0600` permissions. Documented secure erasure practices (`swapoff` $\rightarrow$ `shred -u -z -n 1` $\rightarrow$ `sync` $\rightarrow$ `sdmem -f -ll` $\rightarrow$ `swapon`).
* [x] **`SEC-02` Shell History Protection Notice**: Updated CLI error messages and debian package `postinst` script to instruct operators to set `set +o history` before entering passphrases.
