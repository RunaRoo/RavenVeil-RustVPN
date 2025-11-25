use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info, LevelFilter};

mod app_config;
mod certs;
mod config;
// mod crypto; // REMOVED: Replaced by TLS 1.3
mod logger;
mod tun;
mod tunnel;
mod socks;
mod tui;

use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use crate::app_config::AppConfig;
use crate::config::{Config, SAMPLE_CONFIG};
use crate::logger::StructuredLogger;
use crate::tun::TUN;
use crate::tunnel::{TunnelCommand, TunnelEvent};

const APP_CONFIG_PATH: &str = "appconfig.json";
const DEFAULT_INTERFACE_NAME: &str = "rveil0";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Starts the RavenVeil VPN service with a given config file.
    Up {
        #[clap(value_parser)]
        config_file: String,
    },
    /// Generates a sample config.toml file.
    GenConfig,
    /// Generates TLS certificates for QUIC transport.
    Gencert {
        #[clap(subcommand)]
        command: CertCommands,
    },
}

#[derive(clap::Subcommand, Debug)]
enum CertCommands {
    /// Generate a new CA certificate and key
    Ca,
    /// Generate a new peer certificate and key signed by a CA
    Peer {
        #[clap(long, help = "Comma-separated list of IP addresses and/or DNS names for the peer")]
        peer_names: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // --- CRITICAL: Install AWS-LC Crypto Provider ---
    // This enables support for Post-Quantum algorithms (X25519Kyber768Draft00)
    // and standard TLS 1.3 ciphers via the aws-lc-rs crate.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    if std::env::args().len() > 1 && std::env::args().nth(1) != Some("up".to_string()) {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    let cli = Cli::parse();
    let app_config_prelim = Arc::new(AppConfig::load(APP_CONFIG_PATH).await?);

    match &cli.command {
        Commands::Up { config_file } => {
            let app_config = Arc::new(AppConfig::load(APP_CONFIG_PATH).await?);
            run_vpn(config_file, app_config).await?;
        }
        Commands::GenConfig => {
            fs::write("config.toml", SAMPLE_CONFIG)?;
            println!("Sample config file 'config.toml' created.");
        }
        Commands::Gencert { command } => {
            let cert_dir = &app_config_prelim.certificate_dir;
            fs::create_dir_all(cert_dir)?;
            let ca_cert_path = Path::new(cert_dir).join("ca.pem");
            let ca_key_path = Path::new(cert_dir).join("ca.key");

            match command {
                CertCommands::Ca => {
                    certs::generate_ca(ca_cert_path.to_str().unwrap(), ca_key_path.to_str().unwrap())?;
                    info!("CA certificate and key generated successfully.");
                }
                CertCommands::Peer { peer_names } => {
                    let peer_cert_path = Path::new(cert_dir).join("peer.pem");
                    let peer_key_path = Path::new(cert_dir).join("peer.key");
                    certs::generate_peer_cert(
                        ca_cert_path.to_str().unwrap(),
                        ca_key_path.to_str().unwrap(),
                        peer_cert_path.to_str().unwrap(),
                        peer_key_path.to_str().unwrap(),
                        peer_names,
                    )?;
                    info!("Peer certificate and key generated successfully.");
                }
            }
        }
    }
    Ok(())
}

async fn run_vpn(config_path: &str, app_config: Arc<AppConfig>) -> Result<()> {
    let log_to_std = if app_config.tui_enabled { false } else { app_config.log.log_to_std };
    let log_level = app_config.log.level.parse::<LevelFilter>().unwrap_or(LevelFilter::Info);
    let log_path = if app_config.log.log_path.is_empty() { None } else { Some(app_config.log.log_path.as_str()) };
    StructuredLogger::init(log_level, log_path, log_to_std)?;

    info!("Starting RavenVeil VPN (Pure QUIC/TLS Mode)...");
    let config = Arc::new(Config::load(config_path).await.context("Failed to load VPN config")?);

    // --- Start Tunnel Core (Waveguider) ---
    let tunnel_handle = tunnel::run_tunnel(config.clone(), app_config.clone()).await?;
    let to_tunnel_tx = tunnel_handle.to_tunnel_tx.clone();
    let from_tunnel_rx = tunnel_handle.from_tunnel_rx.clone();

    // --- TUI ---
    if app_config.tui_enabled {
        let peers = tunnel_handle.peers.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::tui::run_tui(peers).await {
                error!("TUI Error: {}", e);
            }
        });
    }

    // --- Shutdown Signal Logic ---
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let shutdown_rx = shutdown_tx.subscribe();

    // Handle PostDown
    let post_down_cmd = config.interface.post_down.clone();
    let mut shutdown_rx_postdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let _ = shutdown_rx_postdown.recv().await;
        if !post_down_cmd.is_empty() {
            let cmd = post_down_cmd.replace("%i", DEFAULT_INTERFACE_NAME);
            info!("Running PostDown command: {}", cmd);
            if let Err(e) = run_cmd_shell(&cmd).await {
                error!("PostDown failed: {}", e);
            }
        }
    });

    // --- Mode Selection ---
    let _task_handle = if app_config.enable_tun {
        info!("Starting in TUN mode...");
        if config.interface.addresses.is_empty() {
            return Err(anyhow::anyhow!("TUN mode requires at least one address in config.toml"));
        }
        let tun = tun::TUNDevice::create(DEFAULT_INTERFACE_NAME, config.clone(), app_config.clone()).await?;
        let tun_reader = Arc::new(tun);
        let tun_writer = tun_reader.try_clone().await?;

        // Build Routing Table (Keys are Strings)
        let routing_table = crate::config::build_routing_table(&config.peers)?;
        let routing_table = Arc::new(tokio::sync::RwLock::new(routing_table));

        // Spawn the tun loop
        tokio::spawn(async move {
            run_tun_loop(tun_reader, tun_writer, to_tunnel_tx, from_tunnel_rx, routing_table, shutdown_rx).await
        })
    } else if app_config.socks5.socks_mode == "client" {
        info!("Starting in SOCKS5 Client mode...");
        let config_clone = config.clone();
        tokio::spawn(async move {
            socks::run_socks_client_mode(app_config, to_tunnel_tx, from_tunnel_rx, config_clone).await
        })
    } else if app_config.socks5.socks_mode == "server" {
        info!("Starting in SOCKS5 Server mode...");
        tokio::spawn(async move {
            socks::run_socks_server_mode(app_config, to_tunnel_tx, from_tunnel_rx).await
        })
    } else {
        info!("Idle mode.");
        tokio::spawn(std::future::pending::<Result<()>>())
    };

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received...");
    let _ = shutdown_tx.send(()); // Trigger PostDown and notify tasks

    // Give a moment for cleanup
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    Ok(())
}

async fn run_tun_loop(
    tun_reader: Arc<Box<dyn TUN>>,
    tun_writer: Box<dyn TUN>,
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    from_tunnel_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<TunnelEvent>>>,
    // FIX: Routing table uses String keys now
    routing_table: Arc<tokio::sync::RwLock<Vec<(ipnetwork::IpNetwork, String)>>>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    let mut from_tunnel_rx_guard = from_tunnel_rx.lock().await;
    info!("VPN TUN Loop running.");
    loop {
        tokio::select! {
            tun_result = tun_reader.read() => {
                match tun_result {
                    Ok(packet) if !packet.is_empty() => {
                         // Find destination based on IP
                        if let Some(dest_id) = crate::tunnel::find_route_for_packet(&packet, &routing_table).await {
                            // Send to Tunnel (Datagram) using destination_id
                            let cmd = TunnelCommand::SendData {
                                destination_id: dest_id,
                                payload: packet.into()
                            };
                            if to_tunnel_tx.send(cmd).await.is_err() { break; }
                        }
                    }
                    Err(e) => { error!("TUN read error: {}", e); break; }
                    _ => {}
                }
            },
            event = from_tunnel_rx_guard.recv() => {
                match event {
                    Some(TunnelEvent::DataReceived { payload, .. }) => {
                        // Write to TUN interface
                        if let Err(e) = tun_writer.write(&payload).await {
                            error!("TUN write error: {}", e);
                        }
                    }
                    None => break,
                }
            },
            _ = shutdown_rx.recv() => {
                info!("TUN loop shutting down.");
                break;
            }
        }
    }
    Ok(())
}

async fn run_cmd_shell(cmd: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    let status = tokio::process::Command::new("cmd").args(["/C", cmd]).status().await?;
    #[cfg(not(target_os = "windows"))]
    let status = tokio::process::Command::new("sh").arg("-c").arg(cmd).status().await?;

    if !status.success() {
        return Err(anyhow::anyhow!("Command failed"));
    }
    Ok(())
}