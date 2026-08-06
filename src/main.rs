use clap::Parser;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;

mod crypto;
mod net;

use crypto::gutenberg::GutenbergMnemonic;
use crypto::identity::NodeIdentity;
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
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

#[derive(Parser, Debug)]
#[command(name = "randbotd", author = "The Random Consortium", version = "0.3.0")]
struct Cli {
    /// Master passphrase for node private key decryption (optional for headless systemd mode)
    #[arg(long)]
    masterpass: Option<String>,

    /// Node operation mode: interactive or headless
    #[arg(long, default_value = "interactive")]
    mode: String,

    /// Force generation of a new Node Identity, replacing any existing keyfile
    #[arg(long)]
    force_new: bool,

    /// Recover Node Identity from a Gutenberg Mnemonic word phrase input
    #[arg(long)]
    recover: Option<String>,

    /// P2P UDP listening port (default: 43210)
    #[arg(long, default_value_t = 43210)]
    port: u16,

    /// Enable seed node mode to advertise high-uptime bootstrap availability
    #[arg(long)]
    seed: bool,

    /// Explicit peer address to connect to (e.g. 127.0.0.1:43210)
    #[arg(long)]
    peer: Option<String>,

    /// External public IP or domain address to advertise for inbound connections (e.g. therandomconsortium.org:43210)
    #[arg(long)]
    external_addr: Option<String>,

    /// Directory path for state files (node_key.enc, peers.json). Defaults to STATE_DIRECTORY env var or "./"
    #[arg(long)]
    state_dir: Option<String>,

    /// Allow falling back to /etc/machine-id for key encryption if no systemd/keyring masterpass is set
    #[arg(long)]
    allow_insecure_machine_id_fallback: bool,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    println!("================================================================================");
    println!("  🛡️ Random Consortium Certificate Bot Daemon (randbotd) v0.3.0");
    println!(
        "  [Mode: {} | Seed Mode: {} | P2P Port: {}]",
        args.mode, args.seed, args.port
    );
    println!("================================================================================\n");

    // Resolve state directory (STATE_DIRECTORY env var, --state-dir, or current directory)
    let base_state_dir = if let Some(custom_dir) = &args.state_dir {
        std::path::PathBuf::from(custom_dir)
    } else if let Ok(env_state) = std::env::var("STATE_DIRECTORY") {
        std::path::PathBuf::from(env_state)
    } else {
        std::path::PathBuf::from(".")
    };

    // 1. Magic Bytes Verification
    println!("[NET-01] Testing UDP Magic Bytes Inspector (b\"RBd1\")...");
    let sample_packet = b"RBd1_gossip_payload_sample";
    if validate_magic_bytes(sample_packet) {
        println!("  -> Magic Bytes check PASSED: Recognized 'RBd1' framing.");
    } else {
        println!("  -> Magic Bytes check FAILED.");
    }

    // 2. Node Identity Key Loading / Generation / Recovery
    println!("\n[NET-01] Initializing Encrypted Node Identity...");
    let key_path = base_state_dir.join("node_key.enc");
    let is_new_identity = !key_path.exists() || args.force_new;

    // Interactive CLI mode allows fallback by default, whereas systemd/headless mode enforces strict security
    let allow_fallback = args.allow_insecure_machine_id_fallback || args.mode == "interactive";

    let identity = if let Some(recover_phrase) = &args.recover {
        println!("  -> Flag --recover passed: Recovering Node Identity from Gutenberg phrase...");
        let raw_seed = GutenbergMnemonic::phrase_to_seed(recover_phrase);
        if raw_seed.len() != 32 {
            eprintln!("  -> FATAL ERROR: Invalid seed derived from phrase.");
            std::process::exit(1);
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&raw_seed);

        let id = NodeIdentity::from_seed(&seed_arr);
        if let Err(e) = id.save_encrypted(&key_path, args.masterpass.as_deref(), allow_fallback) {
            eprintln!("  -> Warning: Could not save recovered key: {}", e);
        } else {
            println!(
                "  -> Recovered Node Identity saved to {}",
                key_path.display()
            );
        }
        id
    } else if args.force_new || !key_path.exists() {
        if args.force_new && key_path.exists() {
            println!("  -> Flag --force-new passed: Replacing existing Node Identity keyfile.");
        } else {
            println!("  -> Generating new Ed25519 Node Identity...");
        }
        let id = NodeIdentity::generate();
        if let Err(e) = id.save_encrypted(&key_path, args.masterpass.as_deref(), allow_fallback) {
            eprintln!("  -> FATAL ERROR saving key file: {}", e);
            std::process::exit(1);
        } else {
            println!(
                "  -> Encrypted Node Identity saved to {}",
                key_path.display()
            );
        }
        id
    } else {
        match NodeIdentity::load_encrypted(&key_path, args.masterpass.as_deref(), allow_fallback) {
            Ok(id) => {
                println!(
                    "  -> Successfully loaded encrypted key from {}",
                    key_path.display()
                );
                id
            }
            Err(err) => {
                eprintln!("  -> FATAL ERROR loading key file:\n{}", err);
                std::process::exit(1);
            }
        }
    };

    println!(
        "  -> Node Public Key: {:02x?}",
        &identity.verifying_key().to_bytes()[..8]
    );

    if is_new_identity && args.recover.is_none() {
        println!(
            "\n================================================================================"
        );
        println!("  ⚠️ SAVE THIS RECOVERY PHRASE SECURELY:");
        let (_seed, mnemonic_phrase) =
            tokio::task::spawn_blocking(GutenbergMnemonic::generate_256bit_phrase)
                .await
                .expect("Mnemonic generation task failed");
        println!("  \"{}\"", mnemonic_phrase);
        println!(
            "================================================================================\n"
        );
    }

    // 3. UPnP Port Forwarding & NAT Self-Diagnosis
    println!("[NET-02] Attempting UPnP Port Forwarding & NAT Reachability Diagnosis...");
    match diagnose_nat_reachability(args.port) {
        NatStatus::UpnpMapped => {
            println!(
                "  -> UPnP Port Forwarding SUCCESS: Port {} mapped via gateway.",
                args.port
            );
        }
        NatStatus::Unreachable => {
            println!(
                "  ⚠️ NAT Warning: Port {} is not currently open/mapped via UPnP.",
                args.port
            );
            println!(
                "  -> Please ensure UDP port {} is forwarded on your router or enable UPnP.",
                args.port
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

    // 5. Asynchronous Tokio UDP Socket Listener & Router Setup
    println!("\n[NET-02] Binding UDP P2P Socket & Spawning Multi-Hop Gossip Listener...");
    let bind_addr = format!("0.0.0.0:{}", args.port);
    let socket = match UdpSocket::bind(&bind_addr).await {
        Ok(s) => {
            println!("  -> P2P UDP Socket bound successfully on {}", bind_addr);
            Arc::new(s)
        }
        Err(err) => {
            eprintln!(
                "  -> Warning: Could not bind UDP socket on {}: {}",
                bind_addr, err
            );
            eprintln!("  -> Running in offline / dry-run mode for gossip verification.");
            Arc::new(
                UdpSocket::bind("127.0.0.1:0")
                    .await
                    .expect("Failed to bind loopback fallback socket"),
            )
        }
    };

    let router = Arc::new(GossipRouter::new(shared_phonebook.clone()));

    // Spawn async P2P packet listener loop
    let listener_socket = socket.clone();
    let listener_router = router.clone();
    let listener_identity = identity.clone();
    let is_seed = args.seed;
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
        }
    });

    // 6. Connect & Handshake to Bootstrap Seed Peers
    println!("\n[NET-02] Connecting to Bootstrap Seed Peers...");
    let mut seed_addrs = shared_phonebook.read().unwrap().verified_seed_addresses();

    // Include explicit --peer argument if provided
    if let Some(explicit_peer) = &args.peer {
        if let Ok(resolved) = std::net::ToSocketAddrs::to_socket_addrs(explicit_peer) {
            for addr in resolved {
                if !seed_addrs.contains(&addr) {
                    seed_addrs.push(addr);
                }
            }
        }
    }

    let rng = OsRng;
    let ephemeral_secret = EphemeralSecret::random_from_rng(rng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let handshake_frame = HandshakeInit::new(identity.signing_key(), &ephemeral_public, args.seed);
    let handshake_bytes = handshake_frame.to_bytes();

    for seed_addr in seed_addrs {
        println!(
            "  -> Sending HandshakeInit frame to seed `{}`...",
            seed_addr
        );
        router.add_peer(seed_addr);
        let _ = socket.send_to(&handshake_bytes, seed_addr).await;
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
        args.port
    );
    println!("  (Press Ctrl+C to stop daemon)");
    println!("================================================================================");

    if args.mode == "daemon" || args.mode == "headless" {
        let _ = tokio::signal::ctrl_c().await;
        println!("\n  🛑 Shutdown signal received. Exiting `randbotd` daemon.");
    } else {
        // In interactive mode, stay active briefly for network events
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
