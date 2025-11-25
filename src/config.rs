use serde::{Deserialize, Serialize};
use std::fs;
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Could not read config file: {0}")]
    ReadFile(#[from] std::io::Error),
    #[error("Could not parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Interface must have at least one address")]
    MissingAddress,
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub interface: InterfaceConfig,
    #[serde(default, rename = "Peer")]
    pub peers: Vec<PeerConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct InterfaceConfig {
    pub listen_port: u16,
    pub addresses: Vec<String>,
    #[serde(default)]
    pub dns: String,

    // Crypto Configuration
    #[serde(default = "default_post_quantum")]
    pub post_quantum: bool,

    #[serde(default)]
    pub post_up: String,
    #[serde(default)]
    pub post_down: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    // Certs
    pub ca_cert_path: String,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PeerConfig {
    // This is now the unique ID for the peer (e.g., "client-1", "server", "alice")
    #[serde(default)]
    pub public_key: String,

    #[serde(default)]
    pub preshared_key: String,

    pub allowed_ips: String,
    #[serde(default)]
    pub endpoint: String,
}

fn default_post_quantum() -> bool {
    true
}

fn default_mtu() -> u16 {
    1280
}

impl Config {
    pub async fn load(path: &str) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;

        if config.interface.addresses.is_empty() {
            log::warn!("'Addresses' field is empty. Ensure this is intended.");
        }
        Ok(config)
    }
}

pub fn build_routing_table(
    peer_configs: &[PeerConfig],
) -> anyhow::Result<Vec<(ipnetwork::IpNetwork, String)>> {
    let mut table = Vec::new();
    for peer in peer_configs {
        let key_id = peer.public_key.clone();
        for cidr_str in peer
            .allowed_ips
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            table.push((ipnetwork::IpNetwork::from_str(cidr_str)?, key_id.clone()));
        }
    }
    table.sort_by(|(a, _), (b, _)| b.prefix().cmp(&a.prefix()));
    Ok(table)
}

pub const SAMPLE_CONFIG: &str = r#"
# RavenVeil Config
[Interface]
ListenPort = 51820
Addresses = ["10.8.0.1/24"]
DNS = "1.1.1.1"
MTU = 1280
PostQuantum = true
CaCertPath = "ca.pem"
CertPath = "peer.pem"
KeyPath = "peer.key"

[[Peer]]
# The Unique Identifier for this peer
PublicKey = "peer_id_1"
# Optional: Leave empty to disable PSK checks
PresharedKey = "some-secret-string"
AllowedIPs = "10.8.0.2/32"
Endpoint = "vpn.example.com:51820"
"#;