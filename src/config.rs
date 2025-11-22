use serde::{Deserialize, Serialize};
use std::fs;
use std::str::FromStr;
use thiserror::Error;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};


#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Could not read config file: {0}")]
    ReadFile(#[from] std::io::Error),
    #[error("Could not parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Interface must have at least one address")]
    MissingAddress,
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
    pub private_key: String,
    #[serde(default)]
    pub kyber_private_key: String,
    pub listen_port: u16,
    pub addresses: Vec<String>,
    #[serde(default)]
    pub dns: String,
    #[serde(default = "default_doh")]
    pub doh: String,
    #[serde(default)]
    pub post_up: String,
    #[serde(default)]
    pub post_down: String,
    #[serde(default = "default_rekey_after_minutes")]
    pub rekey_after_minutes: u64,
    // #[serde(default = "default_handshake_padding_min")]
    // pub handshake_padding_min: usize,
    // #[serde(default = "default_handshake_padding_max")]
    // pub handshake_padding_max: usize,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    pub ca_cert_path: String,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PeerConfig {
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: String,
    pub allowed_ips: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub kyber_public_key: String,
}

// Default values for the configuration
fn default_doh() -> String {
    "".to_string()
}
fn default_rekey_after_minutes() -> u64 {
    3
}
// fn default_handshake_padding_min() -> usize {
//     32
// }
// fn default_handshake_padding_max() -> usize {
//     128
// }
fn default_mtu() -> u16 {
    1420 // A common safe MTU for VPNs
}

impl Config {
    pub async fn load(path: &str) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        // --- FIX: Removed `mut` ---
        let config: Config = toml::from_str(&content)?;

        if config.interface.addresses.is_empty() && !config.interface.private_key.is_empty() {
             // Allow empty addresses if we are in a mode that doesn't need it (like SOCKS)
             // But log a warning if it looks like a misconfiguration.
             // We'll rely on the `EnableTun` flag in appconfig.json to make the final decision.
             // For now, just ensure the config *can* be loaded.
             // Let's add a dummy address if TUN might be expected.
             // A better approach: just check for private_key.
             if config.interface.addresses.is_empty() {
                 log::warn!("'Addresses' field in config.toml is empty. This is only OK if you are *not* using TUN mode.");
                 // We can't return MissingAddress error here as it breaks SOCKS-only mode.
             }
        }
        // if config.interface.handshake_padding_max <= config.interface.handshake_padding_min {
        //     config.interface.handshake_padding_max = config.interface.handshake_padding_min + 96;
        // }
        Ok(config)
    }
} // <-- This closing brace was likely the missing piece

// --- FIX: Add the missing build_routing_table function ---
/// Builds a routing table from the peer configurations.
pub fn build_routing_table(
    peer_configs: &[PeerConfig],
) -> anyhow::Result<Vec<(ipnetwork::IpNetwork, [u8; 32])>> {
    let mut table = Vec::new();
    for peer in peer_configs {
        let pub_key: [u8; 32] = B64.decode(&peer.public_key)?.as_slice().try_into()?;
        for cidr_str in peer
            .allowed_ips
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            table.push((ipnetwork::IpNetwork::from_str(cidr_str)?, pub_key));
        }
    }
    // Sort by prefix length descending, so more specific routes are matched first.
    table.sort_by(|(a, _), (b, _)| b.prefix().cmp(&a.prefix()));
    Ok(table)
}


pub const SAMPLE_CONFIG: &str = r#"
# RavenVeil VPN Configuration File (config.toml)
[Interface]
# Your private X25519 key for the Diffie-Hellman key exchange.
PrivateKey = "<PASTE YOUR X25519 PRIVATE KEY HERE>"

# Your private Kyber1024 key for post-quantum key exchange (optional).
# Kyber1024 Not implemented yet
#KyberPrivateKey = "<PASTE YOUR KYBER1024 PRIVATE KEY HERE>"

# The UDP port the VPN will listen on for incoming connections.
ListenPort = 51820

# The virtual IP address(es) for the TUN interface, in CIDR notation.
# This is REQUIRED for TUN mode, but can be empty for SOCKS-only modes.
Addresses = ["10.8.0.1/24"]

# DNS servers to use for the client (TUN mode only). Comma-separated.
DNS = "1.1.1.1,1.0.0.1"

# DNS-over-HTTPS URL (optional, overrides DNS).
#The DoH Feature not implemented yet, this parameter will be ignored
#DoH = ""

# Set the Maximum Transmission Unit for the link. Default is 1420.
MTU = 1420

# Commands to run after the interface is up or down.
# Example for Linux server (masquerading):
# PostUp = "iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
# PostDown = "iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"
PostUp = ""
PostDown = ""

# --- Security Settings ---
# How often, in minutes, to perform a new handshake to rotate session keys.
RekeyAfterMinutes = 3

# Paths to the TLS certificates, relative to the 'certificate_dir' in appconfig.json.
CaCertPath = "ca.pem"
CertPath = "peer.pem"
KeyPath = "peer.key"

# --- Peer Configuration ---
# Add one [[Peer]] section for each peer you want to connect to.
[[Peer]]
# The peer's public X25519 key.
PublicKey = "<PASTE PEER'S X25519 PUBLIC KEY HERE>"

# The peer's public Kyber1024 key (optional).
# Not implemented yet.
#KyberPublicKey = "<PASTE PEER'S KYBER1024 PUBLIC KEY HERE>"

# A pre-shared key for an extra layer of symmetric-key security (optional).
PresharedKey = "<PASTE THE SAME PRE-SHARED KEY HERE>"

# The IP ranges this peer is allowed to have. This is used for routing.
# For a SOCKS client, set this to "0.0.0.0/0" for the peer that is
# acting as the SOCKS server (exit node).
# For a server, this would be the client's virtual IP (e.g., "10.8.0.2/32").
AllowedIPs = "0.0.0.0/0, ::/0"

# The public endpoint (hostname:port or ip:port) of the peer.
# This is required for clients to connect to a server.
# It can be omitted on a server if it only listens for connections.
Endpoint = "vpn.example.com:51820"
"#;