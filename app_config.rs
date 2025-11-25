use serde::{Deserialize, Serialize};
use std::fs;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppConfigError {
    #[error("Could not read appconfig file: {0}")]
    ReadFile(#[from] std::io::Error),
    #[error("Could not parse appconfig: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct AppConfig {
    pub wintun_path: String,
    pub certificate_dir: String,
    pub log: LogConfig,
    #[serde(default = "default_enable_tun")]
    pub enable_tun: bool,
    #[serde(default)]
    pub tui_enabled: bool,
    #[serde(default = "default_socks5_config")]
    pub socks5: Socks5Config,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct LogConfig {
    pub level: String,
    pub log_path: String,
    pub log_to_std: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Socks5Config {
    #[serde(default = "default_socks_mode")]
    pub socks_mode: String, // "none", "client", "server"
    #[serde(default = "default_socks_listen_address")]
    pub socks_listen_address: String, // e.g., "127.0.0.1:1080"
}

// --- Default functions ---

fn default_enable_tun() -> bool {
    true
}

fn default_socks_mode() -> String {
    "none".to_string()
}

fn default_socks_listen_address() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_socks5_config() -> Socks5Config {
    Socks5Config {
        socks_mode: default_socks_mode(),
        socks_listen_address: default_socks_listen_address(),
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            wintun_path: "wintun.dll".to_string(),
            certificate_dir: "certs".to_string(),
            log: LogConfig {
                level: "info".to_string(),
                log_path: "".to_string(),
                log_to_std: true,
            },
            enable_tun: default_enable_tun(),
            tui_enabled: false,
            socks5: default_socks5_config(),
        }
    }
}

impl AppConfig {
    pub async fn load(path: &str) -> Result<Self, AppConfigError> {
        match fs::read_to_string(path) {
            Ok(content) => Ok(serde_json::from_str(&content)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File not found, create a default one
                let config = AppConfig::default();
                let content = serde_json::to_string_pretty(&config)?;
                fs::write(path, content)?;
                Ok(config)
            }
            Err(e) => Err(e.into()),
        }
    }
}