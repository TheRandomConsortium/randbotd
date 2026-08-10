use clap::Parser;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;

mod cli;
mod config;
mod crypto;
mod net;
mod storage;

use cli::Cli;
use config::DaemonConfig;
use crypto::identity::init_node_identity;
use net::frame::validate_magic_bytes;
use net::gossip::{
    AddressAnnouncementPayload, GossipMessage, DEFAULT_GOSSIP_TTL,
    PAYLOAD_TYPE_ADDRESS_ANNOUNCEMENT, PAYLOAD_TYPE_PING, PAYLOAD_TYPE_VOTE,
};
use net::handshake::HandshakeInit;
use net::nat::{diagnose_nat_reachability, NatStatus};
use net::phonebook::{Phonebook, DEFAULT_SEED_DOMAIN};
use net::router::GossipRouter;
use rand::rngs::OsRng;
use std::path::Path;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    // 0. Declarative Configuration File Loading (NET-03)
    let explicit_config_path = args.config.as_deref().map(Path::new);
    let daemon_cfg = DaemonConfig::load_default_or_create(explicit_config_path);

    // Merge CLI arguments with DaemonConfig
    let port = args.port.or(daemon_cfg.network.port).unwrap_or(43210);
    let seed_mode = args.seed || daemon_cfg.network.seed.unwrap_or(false);
    let explicit_peer = args
        .peer
        .clone()
        .or_else(|| daemon_cfg.network.peer.clone());
    let external_addr = args
        .external_addr
        .clone()
        .or_else(|| daemon_cfg.network.external_addr.clone());
    let do_not_use_clearnet_peers = args.do_not_use_clearnet_peers
        || daemon_cfg
            .network
            .do_not_use_clearnet_peers
            .unwrap_or(false);
    let do_not_advertise_ip =
        args.do_not_advertise_ip || daemon_cfg.network.do_not_advertise_ip.unwrap_or(false);

    if do_not_advertise_ip {
        println!("[NET-09] IP Privacy Enforcement Active (do_not_advertise_ip = true)");
        if let Some(ref ext) = external_addr {
            let is_overlay = ext.contains(".onion") || ext.contains(".i2p");
            if !is_overlay {
                println!(
                    "  ⚠️ PRIVACY WARNING: do_not_advertise_ip is active, but external_addr '{}' is set to a raw IP or clearnet domain!",
                    ext
                );
                println!("     DNS A/AAAA resolution and clearnet routing STILL reveal your public IP address to peers!");
                println!("     To achieve total transport anonymity, set external_addr strictly to a .onion or .i2p hidden service address.\n");
            } else {
                println!(
                    "  -> external_addr '{}' confirmed as overlay hidden service address.\n",
                    ext
                );
            }
        } else {
            println!(
                "  ⚠️ PRIVACY WARNING: do_not_advertise_ip is active, but no external_addr is set!"
            );
            println!("     P2P address announcements will be suppressed completely.\n");
        }
    }

    let tor_socks_proxy = daemon_cfg.privacy.tor_socks_proxy.clone();
    let i2p_proxy_port = daemon_cfg.privacy.i2p_proxy_port;

    if tor_socks_proxy.is_some() || i2p_proxy_port.is_some() {
        println!("[NET-03] Multi-Network Overlay Proxy Routing Policy:");
        if let Some(ref tor_addr) = tor_socks_proxy {
            println!("  -> Tor (.onion):   SOCKS5 Proxy {}", tor_addr);
        }
        if let Some(i2p_port) = i2p_proxy_port {
            println!("  -> I2P (.i2p):     SAM Proxy 127.0.0.1:{}", i2p_port);
        }
        println!("  -> Clearnet:       Native UDP/DNS sockets");
        println!("  ℹ️ Notice: Clearnet peers are NOT routed over Tor/I2P proxies because exit nodes block arbitrary P2P UDP ports.\n");
    }
    // Resolve state directory (args.state_dir, daemon_cfg.storage.state_dir, STATE_DIRECTORY env var, or "./")
    let base_state_dir = if let Some(custom_dir) = &args.state_dir {
        std::path::PathBuf::from(custom_dir)
    } else if let Some(cfg_dir) = &daemon_cfg.storage.state_dir {
        std::path::PathBuf::from(cfg_dir)
    } else if let Ok(env_state) = std::env::var("STATE_DIRECTORY") {
        std::path::PathBuf::from(env_state)
    } else {
        std::path::PathBuf::from(".")
    };

    println!("================================================================================");
    println!("  🛡️ Random Consortium Certificate Bot Daemon (randbotd) v0.3.0");
    println!(
        "  [Mode: {} | Seed Mode: {} | P2P Port: {}]",
        args.mode, seed_mode, port
    );
    println!("================================================================================\n");

    // 1. Magic Bytes Verification
    println!("[NET-01] Testing UDP Magic Bytes Inspector (b\"RBd1\")...");
    let sample_packet = b"RBd1_gossip_payload_sample";
    if validate_magic_bytes(sample_packet) {
        println!("  -> Magic Bytes check PASSED: Recognized 'RBd1' framing.");
    } else {
        println!("  -> Magic Bytes check FAILED.");
    }

    // 2. Node Identity Key Loading / Generation / Recovery
    let identity = init_node_identity(&args, &base_state_dir).await;

    println!(
        "  -> Node Public Key: {:02x?} [Role: {:?}, Voter: {}]",
        &identity.verifying_key().to_bytes()[..8],
        identity.role(),
        identity.is_voter()
    );

    // 3. UPnP Port Forwarding & NAT Self-Diagnosis
    println!("[NET-02] Attempting UPnP Port Forwarding & NAT Reachability Diagnosis...");
    match diagnose_nat_reachability(port) {
        NatStatus::UpnpMapped => {
            println!(
                "  -> UPnP Port Forwarding SUCCESS: Port {} mapped via gateway.",
                port
            );
        }
        NatStatus::Unreachable => {
            println!(
                "  ⚠️ NAT Warning: Port {} is not currently open/mapped via UPnP.",
                port
            );
            println!(
                "  -> Please ensure UDP port {} is forwarded on your router or enable UPnP.",
                port
            );
        }
    }

    // 4. Persistent Peer Phonebook Initialization
    println!("\n[NET-02] Initializing Persistent Peer Phonebook (`./peers.json`)...");
    let pb_path = base_state_dir.join("peers.json");
    let phonebook = match Phonebook::load_from_file(&pb_path) {
        Ok(pb) => {
            println!(
                "  -> Loaded {} peer records from {}",
                pb.peers.len(),
                pb_path.display()
            );
            pb
        }
        Err(e) => {
            println!(
                "  -> Creating new phonebook with default seed `{}`: {}",
                DEFAULT_SEED_DOMAIN, e
            );
            Phonebook::new()
        }
    };
    let shared_phonebook = Arc::new(RwLock::new(phonebook));

    // 4.1. Initialize Transactional Embedded Database (NET-04)
    let db = match storage::db::Database::open(&base_state_dir) {
        Ok(database) => {
            println!(
                "  -> Transactional Database initialized in {}",
                base_state_dir.display()
            );
            Arc::new(database)
        }
        Err(e) => {
            eprintln!(
                "  -> FATAL ERROR initializing database in {}: {}",
                base_state_dir.display(),
                e
            );
            std::process::exit(1);
        }
    };

    // 4.2. Spawn Local Daemon IPC Control Server (NET-08)
    let ipc_socket_path = base_state_dir.join("randbotd.sock");
    let ipc_server = net::ipc::IpcServer::new(ipc_socket_path, shared_phonebook.clone());
    let _ipc_handle = ipc_server.spawn();

    // Broadcast AddressAnnouncement Payload
    let external_addr_str = external_addr.unwrap_or_else(|| format!("127.0.0.1:{}", port));
    let addr_announcement = AddressAnnouncementPayload::new(&external_addr_str, seed_mode);
    let mut ann_bytes = Vec::new();
    ann_bytes.extend_from_slice(&identity.verifying_key().to_bytes());
    ann_bytes.extend_from_slice(&addr_announcement.to_bytes());

    let _ann_msg = GossipMessage::new(
        identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_ADDRESS_ANNOUNCEMENT,
        ann_bytes,
    );
    shared_phonebook.write().unwrap().upsert_peer(
        &identity.verifying_key().to_bytes(),
        &external_addr_str,
        seed_mode,
    );

    // 5. Bind UDP Socket & Initialize Gossip Router
    println!("\n[NET-02] Binding UDP P2P Socket & Spawning Multi-Hop Gossip Listener...");
    let bind_addr = format!("0.0.0.0:{}", port);
    let socket = match UdpSocket::bind(&bind_addr).await {
        Ok(s) => {
            println!("  -> P2P UDP Socket bound successfully on {}", bind_addr);
            Arc::new(s)
        }
        Err(err) => {
            eprintln!(
                "  -> FATAL ERROR binding UDP socket on {}: {}",
                bind_addr, err
            );
            std::process::exit(1);
        }
    };

    let router = Arc::new(GossipRouter::with_database(
        shared_phonebook.clone(),
        db.clone(),
    ));

    // Spawn async P2P packet listener loop
    let listener_socket = socket.clone();
    let listener_router = router.clone();
    let listener_identity = identity.clone();
    let is_headless = identity.is_headless();
    let is_seed = seed_mode;
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        while let Ok((len, src)) = listener_socket.recv_from(&mut buf).await {
            let _ = listener_router
                .process_incoming_packet(
                    &buf[..len],
                    src,
                    &listener_socket,
                    Some(&listener_identity),
                    is_seed,
                    is_headless,
                )
                .await;
        }
    });

    // Spawn Periodic Background Ping / Keepalive Task (30s interval)
    let ping_router = router.clone();
    let ping_socket = socket.clone();
    let ping_identity = identity.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut ping_seq = 1000u64;
        loop {
            interval.tick().await;
            ping_seq += 1;
            let ping_msg = GossipMessage::new(
                ping_identity.signing_key(),
                ping_seq,
                1, // Direct peer ping (TTL=1)
                PAYLOAD_TYPE_PING,
                b"PING_KEEPALIVE".to_vec(),
            );
            ping_router.broadcast(&ping_msg, &ping_socket).await;

            // Prune peers inactive for > 90 seconds (3 missed ping cycles)
            ping_router.prune_inactive_peers(90);

            // Prune seen gossip message IDs older than 1 hour (3600 seconds)
            ping_router.prune_seen_cache(3600);

            // Capacity-Triggered Peer Discovery (NET-08): Only pester peers if active count < target (8)
            let active_count = ping_router.active_peers().len();
            if active_count < 8 {
                let payload =
                    serde_json::to_vec(&crate::net::gossip::GetPeersRequest).unwrap_or_default();
                let msg = GossipMessage::new(
                    ping_identity.signing_key(),
                    ping_seq,
                    1,
                    crate::net::gossip::PAYLOAD_TYPE_GET_PEERS_REQ,
                    payload,
                );
                ping_router.broadcast(&msg, &ping_socket).await;
            }
        }
    });

    // 6. Connect & Handshake to Bootstrap Seed Peers
    println!("\n[NET-02] Connecting to Bootstrap Seed Peers...");
    let mut seed_addrs = shared_phonebook.read().unwrap().verified_seed_addresses();

    // Include explicit --peer argument if provided
    if let Some(peer_str) = &explicit_peer {
        if let Ok(resolved) = std::net::ToSocketAddrs::to_socket_addrs(peer_str.as_str()) {
            for addr in resolved {
                if !seed_addrs.contains(&addr) {
                    seed_addrs.push(addr);
                }
            }
        }
    }

    if do_not_use_clearnet_peers {
        println!("\n  ⚠️ PRIVACY NOTICE: `do_not_use_clearnet_peers` is enabled. Suppressing clearnet seed connections.");
        println!(
            "  -> Note: Default genesis seed (therandomconsortium.org) is a clearnet address."
        );
        println!("  -> You MUST import an .onion or .i2p hidden service seed for the daemon to bootstrap!");
        seed_addrs.clear();
    }

    let rng = OsRng;
    let ephemeral_secret = EphemeralSecret::random_from_rng(rng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let handshake_frame = HandshakeInit::new(
        identity.signing_key(),
        &ephemeral_public,
        seed_mode,
        is_headless,
    );
    let handshake_bytes = handshake_frame.to_bytes();

    let get_peers_payload =
        serde_json::to_vec(&crate::net::gossip::GetPeersRequest).unwrap_or_default();
    let get_peers_init_msg = GossipMessage::new(
        identity.signing_key(),
        100,
        1,
        crate::net::gossip::PAYLOAD_TYPE_GET_PEERS_REQ,
        get_peers_payload,
    );

    for seed_addr in seed_addrs {
        println!(
            "  -> Sending HandshakeInit frame & GetPeersRequest to seed `{}`...",
            seed_addr
        );
        router.add_peer(seed_addr);
        let _ = socket.send_to(&handshake_bytes, seed_addr).await;
        let _ = socket
            .send_to(&get_peers_init_msg.to_bytes(), seed_addr)
            .await;
    }

    // 7. Broadcast Signed Address Announcement to Swarm (only if --external-addr is configured)
    if let Some(ext_addr) = &args.external_addr {
        let addr_announcement = AddressAnnouncementPayload::new(ext_addr, args.seed);
        let gossip_addr = GossipMessage::new(
            identity.signing_key(),
            1,
            DEFAULT_GOSSIP_TTL,
            PAYLOAD_TYPE_ADDRESS_ANNOUNCEMENT,
            addr_announcement.to_bytes(),
        );

        router.broadcast(&gossip_addr, &socket).await;
        println!(
            "  -> Broadcasted Signed Address Announcement (`{}`)",
            ext_addr
        );
    }

    // 8. Demonstrate Vote Gossip & CA Declaration Relaying
    let vote_payload = b"Vote_TW:domain=randbot.hns:pow_nonce=0x4a91b".to_vec();
    let gossip_vote = GossipMessage::new(
        identity.signing_key(),
        2,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_VOTE,
        vote_payload,
    );
    router.broadcast(&gossip_vote, &socket).await;
    println!(
        "  -> Broadcasted Signed Gossip Vote (ID: {:02x?})",
        &gossip_vote.msg_id[..4]
    );

    let ca_payload = b"CA_DECLARATION:Issuer=TheRandomConsortium:Domain=*.hns".to_vec();
    let gossip_ca = GossipMessage::new(
        identity.signing_key(),
        3,
        DEFAULT_GOSSIP_TTL,
        crate::net::gossip::PAYLOAD_TYPE_CA_DECLARATION,
        ca_payload,
    );
    router.broadcast(&gossip_ca, &socket).await;
    println!(
        "  -> Broadcasted Signed Root CA Declaration (ID: {:02x?})",
        &gossip_ca.msg_id[..4]
    );

    let _all_resolved_peers = shared_phonebook.read().unwrap().resolve_peer_addresses();

    println!("\n================================================================================");
    println!(
        "  🟢 `randbotd` v0.3.0 running. Active P2P multi-hop gossip swarm listening on port {}.",
        port
    );
    println!("  (Press Ctrl+C to stop daemon)");
    println!("================================================================================");

    let _ = tokio::signal::ctrl_c().await;
    println!("\n  🛑 Shutdown signal received. Exiting `randbotd` daemon.");
}
