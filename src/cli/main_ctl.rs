use clap::{Args, Parser, Subcommand};
use randbotd::cli::client::{resolve_socket_path, send_command};
use randbotd::cli::dashboard::run_dashboard_server;
use randbotd::cli::format::{print_cas, print_offers, print_peers, print_status};
use randbotd::net::ipc::IpcCommand;
use randbotd::proof::DomainNetworkType;

#[derive(Parser, Debug)]
#[command(
    name = "randbotctl",
    author = "The Random Consortium",
    version,
    about = "Interactive CLI & CA Command Center for randbotd"
)]
struct CtlApp {
    /// Path to randbotd IPC unix domain socket (defaults to standard state_dir/randbotd.sock)
    #[arg(long, global = true)]
    socket: Option<String>,

    /// Output responses in raw JSON format
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect node status, public key identity, and storage summary
    Status,

    /// Manage and inspect Root and Intermediate Certificate Authorities (CA-01 / CA-06)
    Ca {
        #[command(subcommand)]
        command: CaCommands,
    },

    /// Inspect certificate offer catalogs and issuance profiles (CA-12)
    Offer {
        #[command(subcommand)]
        command: OfferCommands,
    },

    /// Manage certificate lifecycle and revocations (CA-06 / CA-07)
    Cert {
        #[command(subcommand)]
        command: CertCommands,
    },

    /// Emit and query bad-domain purges across the P2P Web-of-Trust (CA-07)
    Purge {
        #[command(subcommand)]
        command: PurgeCommands,
    },

    /// Query and import P2P network peers
    Peer {
        #[command(subcommand)]
        command: PeerCommands,
    },

    /// Inspect distributed custodian swarm contracts and worker shares (CA-11)
    Swarm {
        #[command(subcommand)]
        command: SwarmCommands,
    },

    /// Launch the interactive localhost CA Command Center Web Dashboard (CA-06)
    Dashboard(DashboardArgs),
}

#[derive(Subcommand, Debug)]
enum CaCommands {
    /// List all registered Root and Intermediate CAs
    List,
    /// Get details of a specific CA by hex ID
    Get {
        /// CA ID in 64-character hexadecimal
        ca_id: String,
    },
    /// Publish or draft a new CA declaration
    Publish(CaPublishArgs),
}

#[derive(Args, Debug)]
struct CaPublishArgs {
    /// Common Name (CN) for the CA
    #[arg(long)]
    name: String,
    /// Organization name (O)
    #[arg(long)]
    org: Option<String>,
    /// Organizational Unit (OU)
    #[arg(long)]
    unit: Option<String>,
    /// Contact email address
    #[arg(long)]
    email: Option<String>,
    /// Country code (ISO 3166-1 alpha-2, e.g. ES, US, DE)
    #[arg(long)]
    country: Option<String>,
    /// Declare as Intermediate CA rather than self-signed Root CA
    #[arg(long)]
    intermediate: bool,
    /// Path length constraint for intermediate CAs
    #[arg(long)]
    path_len: Option<u32>,
    /// Save as draft without broadcasting to P2P network
    #[arg(long)]
    draft: bool,
}

#[derive(Subcommand, Debug)]
enum OfferCommands {
    /// List certificate profiles in offer catalog
    List {
        /// Filter by specific CA ID hex
        #[arg(long)]
        ca_id: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum CertCommands {
    /// Revoke a certificate by serial number and issue updated CRL
    Revoke {
        /// Issuing CA ID hex
        #[arg(long)]
        ca_id: String,
        /// Certificate serial number in hexadecimal
        #[arg(long)]
        serial: String,
        /// Revocation reason code (1=keyCompromise, 3=affiliationChanged, 4=superseded, 5=cessationOfOperation, 9=privilegeWithdrawn)
        #[arg(long)]
        reason: Option<u8>,
    },
}

#[derive(Subcommand, Debug)]
enum PurgeCommands {
    /// Emit a bad-domain purge with PoW strike (automatically revokes active certs)
    Emit(PurgeEmitArgs),
    /// List all active domain purges
    List {
        /// Filter by issuing CA ID hex
        #[arg(long)]
        ca_id: Option<String>,
    },
    /// Query active purge record for a specific domain
    Get {
        /// Target domain name
        domain: String,
    },
}

#[derive(Args, Debug)]
struct PurgeEmitArgs {
    /// Issuing CA ID hex
    #[arg(long)]
    ca_id: String,
    /// Offending domain name
    #[arg(long)]
    domain: String,
    /// Reason string (e.g. malware, phishing, utw, terms)
    #[arg(long, default_value = "utw")]
    reason: String,
    /// Detailed description of the violation / strike evidence
    #[arg(long)]
    description: String,
    /// Target certificate serial hex to explicitly cross-revoke
    #[arg(long)]
    serial: Option<String>,
}

#[derive(Subcommand, Debug)]
enum PeerCommands {
    /// List known peers in phonebook
    List,
    /// Manually import and dial a peer address (e.g. 1.2.3.4:43210)
    Import {
        /// Peer socket address
        address: String,
    },
}

#[derive(Subcommand, Debug)]
enum SwarmCommands {
    /// List active custodians and worker shares for a CA
    List {
        /// Target CA ID hex
        ca_id: String,
    },
}

#[derive(Args, Debug)]
struct DashboardArgs {
    /// Local HTTP listening port
    #[arg(long, default_value = "43211")]
    port: u16,

    /// Automatically open browser on launch
    #[arg(long)]
    open: bool,
}

#[tokio::main]
async fn main() {
    let args = CtlApp::parse();
    let socket_path = resolve_socket_path(args.socket.as_deref());

    match args.command {
        Commands::Dashboard(d_args) => {
            if let Err(e) = run_dashboard_server(d_args.port, socket_path, d_args.open).await {
                eprintln!("Dashboard Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Status => match send_command(&socket_path, IpcCommand::GetNodeStatus).await {
            Ok(resp) => print_status(&resp, args.json),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Commands::Ca { command } => match command {
            CaCommands::List => match send_command(&socket_path, IpcCommand::ListCas).await {
                Ok(resp) => print_cas(&resp, args.json),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            },
            CaCommands::Get { ca_id } => {
                match send_command(&socket_path, IpcCommand::GetCa { ca_id_hex: ca_id }).await {
                    Ok(resp) => println!("{}", resp),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            CaCommands::Publish(p) => {
                let cmd = IpcCommand::PublishCa {
                    ca_id_hex: None,
                    common_name: p.name,
                    organization: p.org,
                    organizational_unit: p.unit,
                    locality: None,
                    state_or_province: None,
                    country: p.country,
                    email: p.email,
                    is_intermediate: p.intermediate,
                    path_len_constraint: p.path_len,
                    is_draft: if p.draft { Some(true) } else { None },
                    supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
                    permitted_subtrees: None,
                };
                match send_command(&socket_path, cmd).await {
                    Ok(resp) => println!("✓ {}", resp),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Offer { command } => match command {
            OfferCommands::List { ca_id } => {
                match send_command(&socket_path, IpcCommand::ListOffers { ca_id_hex: ca_id }).await
                {
                    Ok(resp) => print_offers(&resp, args.json),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Cert { command } => match command {
            CertCommands::Revoke {
                ca_id,
                serial,
                reason,
            } => {
                let cmd = IpcCommand::RevokeCert {
                    ca_id_hex: ca_id,
                    serial_hex: serial,
                    reason,
                };
                match send_command(&socket_path, cmd).await {
                    Ok(resp) => println!("✓ {}", resp),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Purge { command } => match command {
            PurgeCommands::Emit(p) => {
                let cmd = IpcCommand::PurgeDomain {
                    ca_id_hex: p.ca_id,
                    domain: p.domain,
                    serial_hex: p.serial,
                    reason: Some(p.reason),
                    description: p.description,
                    strike_evidence: None,
                    ttl_seconds: None,
                };
                match send_command(&socket_path, cmd).await {
                    Ok(resp) => println!("✓ {}", resp),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            PurgeCommands::List { ca_id } => {
                match send_command(&socket_path, IpcCommand::ListPurges { ca_id_hex: ca_id }).await
                {
                    Ok(resp) => println!("{}", resp),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            PurgeCommands::Get { domain } => {
                match send_command(&socket_path, IpcCommand::GetPurge { domain }).await {
                    Ok(resp) => println!("{}", resp),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Peer { command } => match command {
            PeerCommands::List => match send_command(&socket_path, IpcCommand::ListPeers).await {
                Ok(resp) => print_peers(&resp, args.json),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            },
            PeerCommands::Import { address } => {
                match send_command(&socket_path, IpcCommand::ImportPeer { peer_addr: address })
                    .await
                {
                    Ok(resp) => println!("✓ {}", resp),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Swarm { command } => match command {
            SwarmCommands::List { ca_id } => {
                match send_command(
                    &socket_path,
                    IpcCommand::ListCustodians { ca_id_hex: ca_id },
                )
                .await
                {
                    Ok(resp) => println!("{}", resp),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
    }
}
