# 🛠️ `randbotd` Chore List & Technical Debt

This document tracks minor maintenance tasks, refactoring needs, infrastructure improvements, and technical debt accumulated during the development of `randbotd`.

---

## 🧹 Active Chores & Technical Debt

* [ ] **`ENTROPY-01` Configurable Plaintext Entropy Source URLs (`[entropy] source_urls`)**: Allow operators to configure arbitrary plaintext URLs in `randbotd.toml` (e.g. `[entropy] source_urls = ["http://calories.tplinkdns.com/insultos/insultos.csv", "https://example.org/corpus.txt", "..."]`) as dynamic Gutenberg drilldown alternatives. The engine fetches text content (HTML, CSV, TXT, JSON — strictly excluding binary/PDF/multipart/`application/octet-stream`), splits words, deduplicates the corpus vocabulary, computes true Shannon entropy ($H = \log_2(N)$), and samples CSPRNG words across iterations until reaching 256 bits.

---

## ✅ Completed Chores

* [x] **`CA-ID-01` Bind `ca_id` to Owner Node Pubkey (composite)**: Updated `compute_ca_id` in [`src/crypto/ca.rs`](file:///home/mreugenej7/git/randbotd/src/crypto/ca.rs) to derive CA IDs deterministically via `SHA-256("randbotd_v1_ca_identity_domain:" || common_name || ":" || node_pubkey_bytes)`.
* [x] **`DNS-01` Punycode / IDN Normalization Before Wire-Format Queries**: Integrated `idna::punycode::encode_str` into `build_dns_query_packet` in [`src/crypto/dns.rs`](file:///home/mreugenej7/git/randbotd/src/crypto/dns.rs) to convert Unicode domain labels to Punycode ACE wire format (`xn--...`) prior to on-wire DNS resolution.
* [x] **`NET-02` Gossip Router Seen Cache Eviction**: Implemented timestamp-bounded eviction for `GossipRouter.seen_cache` (`HashMap<[u8; 32], u64>`) to purge expired message IDs older than 1 hour (3600s) during periodic keepalive cycles.
* [x] **`SEC-01` Mnemonic Log Leak Prevention & Secure Deletion**: Prevented recovery phrase leakage into systemd `journalctl` logs. Written generated phrases to RAM-backed file (`/dev/shm/randbotd_mnemonic_<PID>.txt`) with strict `0600` permissions. Documented secure erasure practices (`swapoff` $\rightarrow$ `shred -u -z -n 1` $\rightarrow$ `sync` $\rightarrow$ `sdmem -f -ll` $\rightarrow$ `swapon`).
* [x] **`SEC-02` Shell History Protection Notice**: Updated CLI error messages and debian package `postinst` script to instruct operators to set `set +o history` before entering passphrases.

