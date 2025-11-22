use super::*;
use crate::{app_config::AppConfig, config::Config};
use anyhow::Result;
use log::{info, warn, error};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use std::net::SocketAddr;

// --- Defined TunnelHandle here so it is visible to mod.rs ---
pub struct TunnelHandle {
    pub to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    pub from_tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelEvent>>>,
    pub peers: PeerMap,
}

pub async fn run_tunnel(
    config: Arc<Config>,
    app_config: Arc<AppConfig>,
) -> Result<TunnelHandle> {
    let (to_tunnel_tx, to_tunnel_rx) = mpsc::channel(1024);
    let (from_tunnel_tx, from_tunnel_rx) = mpsc::channel(1024);

    let peers = super::routing::build_peer_map(&config.peers).await?;

    // --- Endpoint Setup ---
    let server_config = super::util::load_server_config(&config, &app_config)?;
    let client_config = super::util::load_client_config(&config, &app_config)?;

    let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.interface.listen_port));

    let mut endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_config);

    // Spawn Core
    tokio::spawn(core_loop(
        config.clone(),
        app_config.clone(),
        peers.clone(),
        to_tunnel_rx,
        from_tunnel_tx.clone(),
        endpoint,
    ));

    Ok(TunnelHandle {
        to_tunnel_tx,
        from_tunnel_rx: Arc::new(Mutex::new(from_tunnel_rx)),
        peers,
    })
}

async fn core_loop(
    config: Arc<Config>,
    _app_config: Arc<AppConfig>,
    peers: PeerMap,
    mut to_tunnel_rx: mpsc::Receiver<TunnelCommand>,
    from_tunnel_tx: mpsc::Sender<TunnelEvent>,
    endpoint: quinn::Endpoint,
) {
    info!("Waveguider core online. Listening on {}", endpoint.local_addr().unwrap());

    let our_static = match crate::tunnel::util::load_our_static_key(&config) {
        Ok(k) => k,
        Err(e) => {
            error!("Critical: Failed to load private key: {}. Tunnel aborting.", e);
            return;
        }
    };

    // 1. Spawn Outgoing Connection Managers (Client Logic)
    for peer in peers.read().await.values() {
        let p = peer.clone();
        let c = config.clone();
        let ep = endpoint.clone();
        let tx = from_tunnel_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = super::stream::manage_peer_connection(p, c, ep, tx).await {
                warn!("Peer manager error: {}", e);
            }
        });
    }

    // 2. Spawn Incoming Connection Acceptor (Server Logic)
    let ep_clone = endpoint.clone();
    let peers_server = peers.clone();
    let tx_server = from_tunnel_tx.clone();
    let our_static_server = our_static.clone();

    tokio::spawn(async move {
        while let Some(conn) = ep_clone.accept().await {
            let p_map = peers_server.clone();
            let tx = tx_server.clone();
            let static_key = our_static_server.clone();

            tokio::spawn(async move {
                match conn.await {
                    Ok(connection) => {
                        info!("Incoming connection from {}", connection.remote_address());

                        match connection.accept_bi().await {
                            Ok(stream) => {
                                if let Err(e) = super::handshake::handle_incoming_handshake(
                                    stream,
                                    &static_key,
                                    p_map,
                                    tx
                                ).await {
                                    warn!("Handshake failed for {}: {}", connection.remote_address(), e);
                                }
                            }
                            Err(e) => warn!("Failed to accept stream from {}: {}", connection.remote_address(), e),
                        }
                    }
                    Err(e) => warn!("Connection accept failed: {}", e),
                }
            });
        }
    });

    // 3. Outbound Data Loop (The Door)
    while let Some(cmd) = to_tunnel_rx.recv().await {
        match cmd {
            TunnelCommand::SendData { destination_key, payload } => {
                if let Err(_e) = super::door::send_packet(destination_key, payload, &peers).await {
                    // warn!("Send failed: {}", _e);
                }
            }
        }
    }
}