use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "randbotd", author = "The Random Consortium", version = "3.0.0")]
pub struct Cli {
    /// Path to TOML configuration file (defaults to /etc/randbotd/randbotd.toml or ./randbotd.toml)
    #[arg(long)]
    pub config: Option<String>,

    /// Master passphrase for node private key decryption (optional for headless systemd mode)
    #[arg(long)]
    pub masterpass: Option<String>,

    /// Node operation mode: daemon (default) or headless (systemd service)
    #[arg(long, default_value = "daemon")]
    pub mode: String,

    /// Force generation of a new Node Identity, replacing any existing keyfile
    #[arg(long)]
    pub force_new: bool,

    /// Recover Node Identity from a Gutenberg Mnemonic word phrase input
    #[arg(long)]
    pub recover: Option<String>,

    /// P2P UDP listening port (overrides config file default 43210)
    #[arg(long)]
    pub port: Option<u16>,

    /// Enable seed node mode to advertise high-uptime bootstrap availability
    #[arg(long)]
    pub seed: bool,

    /// Explicit peer address to connect to (e.g. 127.0.0.1:43210)
    #[arg(long)]
    pub peer: Option<String>,

    /// External public IP or domain address to advertise for inbound connections (e.g. therandomconsortium.org:43210)
    #[arg(long)]
    pub external_addr: Option<String>,

    /// Directory path for state files (node_key.enc, peers.json). Defaults to STATE_DIRECTORY env var or "./"
    #[arg(long)]
    pub state_dir: Option<String>,

    /// Suppress connecting to clearnet IPv4/v6 peers, requiring .onion or .i2p hidden seeds
    #[arg(long)]
    pub do_not_use_clearnet_peers: bool,

    /// Suppress broadcasting raw local IP socket address, enforcing external_addr usage
    #[arg(long)]
    pub do_not_advertise_ip: bool,

    /// Allow falling back to /etc/machine-id for key encryption if no systemd/keyring masterpass is set
    #[arg(long)]
    pub allow_insecure_machine_id_fallback: bool,

    /// Allow falling back to embedded Crypto Anarchist Manifesto corpus if external Project Gutenberg servers are unreachable
    #[arg(long)]
    pub allow_entropy_fallback: bool,
}
