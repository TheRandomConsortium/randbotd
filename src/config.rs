use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub port: Option<u16>,
    pub seed: Option<bool>,
    pub peer: Option<String>,
    pub external_addr: Option<String>,
    pub do_not_advertise_ip: Option<bool>,
    pub do_not_use_clearnet_peers: Option<bool>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            port: Some(43210),
            seed: Some(false),
            peer: None,
            external_addr: None,
            do_not_advertise_ip: Some(false),
            do_not_use_clearnet_peers: Some(false),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivacyConfig {
    pub tor_socks_proxy: Option<String>,
    pub i2p_proxy_port: Option<u16>,
    pub i2p_sam_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct HandshakeConfig {
    pub hns_dns_port: Option<u16>,
    pub hns_recursive_port: Option<u16>,
    pub hns_dns_mode: Option<String>,
    pub hns_dns_target: Option<String>,
    pub upstream_dns_resolver: Option<String>,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            hns_dns_port: Some(53493),
            hns_recursive_port: Some(53492),
            hns_dns_mode: Some("udp".to_string()),
            hns_dns_target: Some("daemon".to_string()),
            upstream_dns_resolver: Some("9.9.9.9:53".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageConfig {
    pub state_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DaemonConfig {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub privacy: PrivacyConfig,
    #[serde(default)]
    pub handshake: HandshakeConfig,
    #[serde(default)]
    pub storage: StorageConfig,
}

impl DaemonConfig {
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Could not read config file {}: {}", path.display(), e))?;
        toml::from_str(&content)
            .map_err(|e| format!("Invalid TOML config in {}: {}", path.display(), e))
    }

    pub fn load_default_or_create(explicit_path: Option<&Path>) -> Self {
        if let Some(p) = explicit_path {
            if let Ok(cfg) = Self::load_from_file(p) {
                println!("  -> Loaded declarative configuration from {}", p.display());
                return cfg;
            }
        }

        let candidates = [
            PathBuf::from("/etc/randbotd/randbotd.toml"),
            PathBuf::from("./randbotd.toml"),
        ];

        for path in &candidates {
            if path.exists() {
                if let Ok(cfg) = Self::load_from_file(path) {
                    println!(
                        "  -> Loaded declarative configuration from {}",
                        path.display()
                    );
                    return cfg;
                }
            }
        }

        Self::default()
    }

    /// Checks if Tor SOCKS proxy is configured
    pub fn has_tor_support(&self) -> bool {
        self.privacy
            .tor_socks_proxy
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    }

    /// Checks if I2P proxy port or SAM port is configured
    pub fn has_i2p_support(&self) -> bool {
        self.privacy.i2p_proxy_port.map(|p| p > 0).unwrap_or(false)
            || self.privacy.i2p_sam_port.map(|p| p > 0).unwrap_or(false)
    }

    /// Checks if Handshake DNS resolution is enabled
    pub fn has_hns_support(&self) -> bool {
        matches!(
            self.handshake.hns_dns_mode.as_deref(),
            Some("udp") | Some("doh")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_config_toml_roundtrip() {
        let raw_toml = r#"
[network]
port = 43211
seed = true
do_not_use_clearnet_peers = true

[privacy]
tor_socks_proxy = "127.0.0.1:9050"
i2p_proxy_port = 7656

[handshake]
hns_dns_port = 53493
hns_recursive_port = 53492
hns_dns_mode = "udp"
hns_dns_target = "daemon"
upstream_dns_resolver = "9.9.9.9:53"
"#;
        let config: DaemonConfig = toml::from_str(raw_toml).expect("Failed to parse TOML");
        assert_eq!(config.network.port, Some(43211));
        assert_eq!(config.network.seed, Some(true));
        assert_eq!(config.network.do_not_use_clearnet_peers, Some(true));
        assert_eq!(
            config.privacy.tor_socks_proxy,
            Some("127.0.0.1:9050".to_string())
        );
        assert!(config.has_tor_support());
        assert!(config.has_i2p_support());
        assert!(config.has_hns_support());
        assert_eq!(
            config.handshake.upstream_dns_resolver,
            Some("9.9.9.9:53".to_string())
        );
    }
}
