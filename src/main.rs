use clap::Parser;
use std::path::Path;

mod crypto;
mod net;

use crypto::gutenberg::GutenbergMnemonic;
use crypto::identity::NodeIdentity;
use net::frame::validate_magic_bytes;
use net::handshake::HandshakeInit;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use rand::rngs::OsRng;

#[derive(Parser, Debug)]
#[command(name = "randbotd", author = "The Random Consortium", version = "0.2.0")]
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
}

fn main() {
    let args = Cli::parse();
    println!("Random Consortium's Certificate Bot Daemon (randbotd) running");
    println!("  [Mode: {}]", args.mode);

    // 1. Magic Bytes Inspector Verification
    println!("\n[NET-01] Testing UDP Magic Bytes Inspector (b\"RBd1\")...");
    let sample_packet = b"RBd1_gossip_payload_sample";
    if validate_magic_bytes(sample_packet) {
        println!("  -> Magic Bytes check PASSED: Recognized 'RBd1' framing.");
    } else {
        println!("  -> Magic Bytes check FAILED.");
    }

    // 2. Node Identity Key Loading / Generation / Recovery / Force-New
    println!("\n[NET-01] Initializing Encrypted Node Identity...");
    let key_path = Path::new("./node_key.enc");
    let is_new_identity = !key_path.exists() || args.force_new;

    let identity = if let Some(recover_phrase) = &args.recover {
        println!("  -> Flag --recover passed: Recovering Node Identity from Gutenberg Mnemonic phrase...");
        let raw_seed = GutenbergMnemonic::phrase_to_seed(recover_phrase);
        if raw_seed.len() != 32 {
            eprintln!("  -> FATAL ERROR: Invalid seed derived from phrase.");
            std::process::exit(1);
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&raw_seed);

        let id = NodeIdentity::from_seed(&seed_arr);
        if let Err(e) = id.save_encrypted(key_path, args.masterpass.as_deref()) {
            eprintln!("  -> Warning: Could not save recovered key: {}", e);
        } else {
            println!("  -> Recovered Node Identity saved and encrypted to {}", key_path.display());
        }
        id
    } else if args.force_new || !key_path.exists() {
        if args.force_new && key_path.exists() {
            println!("  -> Flag --force-new passed: Destroying/replacing existing Node Identity keyfile.");
            println!("  -> Note: Previous node state will be perceived by the network as owned by another peer.");
        } else {
            println!("  -> No keyfile found. Generating new Ed25519 Node Identity...");
        }
        let id = NodeIdentity::generate();
        if let Err(e) = id.save_encrypted(key_path, args.masterpass.as_deref()) {
            println!("  -> Warning: Could not save encrypted key: {}", e);
        } else {
            println!("  -> Encrypted Node Identity saved to {}", key_path.display());
        }
        id
    } else {
        match NodeIdentity::load_encrypted(key_path, args.masterpass.as_deref()) {
            Ok(id) => {
                println!("  -> Successfully loaded encrypted key from {}", key_path.display());
                id
            }
            Err(err) => {
                eprintln!("  -> FATAL ERROR loading key file: {}", err);
                eprintln!("  -> Aborting daemon execution to protect node identity.");
                std::process::exit(1);
            }
        }
    };

    println!("  -> Node Public Key: {:02x?}", &identity.verifying_key().to_bytes()[..8]);

    // 3. Gutenberg 256-bit Mnemonic Generation ("Fuck BIP39")
    if is_new_identity && args.recover.is_none() {
        println!("\n================================================================================");
        println!("  ⚠️ SAVE THIS MOTHERFUCKER OR YOU WON'T BE ABLE TO RECOVER YOUR NODE!");
        println!("================================================================================");
        let (_seed, mnemonic_phrase) = GutenbergMnemonic::generate_256bit_phrase();
        println!("  Gutenberg Recovery Mnemonic Phrase:");
        println!("  \"{}\"", mnemonic_phrase);
        println!("================================================================================\n");
    }

    // 4. Handshake Framing Construction & Verification
    println!("\n[NET-01] Constructing P2P Handshake Framing (`HandshakeInit`)...");
    let mut rng = OsRng;
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let handshake_frame = HandshakeInit::new(identity.signing_key(), &ephemeral_public);
    let raw_bytes = handshake_frame.to_bytes();
    println!("  -> Serialized Handshake Frame: {} bytes (starts with magic '{:?}')", 
        raw_bytes.len(), 
        String::from_utf8_lossy(&raw_bytes[..4])
    );

    match HandshakeInit::from_bytes(&raw_bytes) {
        Ok(verified) => {
            println!("  -> P2P Handshake Signature Verification: PASSED");
            println!("  -> Peer Public Key Match: {}", verified.sender_pubkey == identity.verifying_key().to_bytes());
        }
        Err(e) => {
            println!("  -> P2P Handshake Signature Verification FAILED: {}", e);
        }
    }
}
