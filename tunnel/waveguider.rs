use super::*;
use crate::{app_config::AppConfig, config::Config};
use anyhow::Result;
use log::{info, warn, error, debug};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use std::net::SocketAddr;

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

    let server_config = super::util::load_server_config(&config, &app_config)?;
    let client_config = super::util::load_client_config(&config, &app_config)?;

    let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.interface.listen_port));

    let mut endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_config);

    tokio::spawn(core_loop(
        peers.clone(),
        to_tunnel_rx,
        from_tunnel_tx.clone(),
        endpoint,
        config.clone(), // Pass config to look up global settings if needed
    ));

    Ok(TunnelHandle {
        to_tunnel_tx,
        from_tunnel_rx: Arc::new(Mutex::new(from_tunnel_rx)),
        peers,
    })
}

async fn core_loop(
    peers: PeerMap,
    mut to_tunnel_rx: mpsc::Receiver<TunnelCommand>,
    from_tunnel_tx: mpsc::Sender<TunnelEvent>,
    endpoint: quinn::Endpoint,
    _config: Arc<Config>,
) {
    info!("Waveguider online via QUIC Datagrams. Listening on {}", endpoint.local_addr().unwrap());

    // 1. Client Logic: Connect to peers that have a defined endpoint
    for peer in peers.read().await.values() {
        let p = peer.clone();
        let ep = endpoint.clone();
        let tx = from_tunnel_tx.clone();

        if !p.config.endpoint.is_empty() {
            tokio::spawn(async move {
                if let Err(e) = super::stream::manage_peer_connection(p, ep, tx).await {
                    warn!("Peer connection manager ended: {}", e);
                }
            });
        }
    }

    // 2. Server Logic: Accept incoming connections
    let ep_clone = endpoint.clone();
    let peers_server = peers.clone();
    let tx_server = from_tunnel_tx.clone();

    tokio::spawn(async move {
        while let Some(conn) = ep_clone.accept().await {
            let p_map = peers_server.clone();
            let tx = tx_server.clone();

            tokio::spawn(async move {
                match conn.await {
                    Ok(connection) => {
                        let remote_addr = connection.remote_address();
                        info!("Incoming connection established from {}", remote_addr);
                        
                        // We need to associate this connection with a Peer struct to track stats
                        // and manage the session state.

                        let mut matched_peer: Option<Arc<Peer>> = None;
                        let peers_guard = p_map.read().await;

                        // Strategy 1: Match by specific IP endpoint (if known)
                        for peer in peers_guard.values() {
                            let endpoint_guard = peer.endpoint_addr.read().await;
                            if let Some(endpoint) = *endpoint_guard {
                                if endpoint.ip() == remote_addr.ip() {
                                    matched_peer = Some(peer.clone());
                                    debug!("Matched peer {} by IP", peer.config.public_key);
                                    break;
                                }
                            }
                        }

                        // Strategy 2: If no IP match, check for a "Dynamic" or "Catch-all" peer.
                        // In this config system, we assume a peer with empty Endpoint is dynamic/passive.
                        if matched_peer.is_none() {
                            for peer in peers_guard.values() {
                                if peer.config.endpoint.is_empty() {
                                    matched_peer = Some(peer.clone());
                                    debug!("Assigned to dynamic/passive peer config: {}", peer.config.public_key);
                                    // Update the dynamic peer's endpoint to reflect the current connection
                                    *peer.endpoint_addr.write().await = Some(remote_addr);
                                    break;
                                }
                            }
                        }

                        drop(peers_guard); // Release lock

                        if let Some(peer) = matched_peer {
                            info!("Connection from {} mapped to Peer ID: {}", remote_addr, peer.config.public_key);

                            // Update connection state
                            *peer.connection.write().await = Some(connection.clone());
                            let _ = peer.session_ready_tx.send(true);

                            // Spawn the data processor
                            super::door::spawn_data_processor(peer.clone(), connection, tx).await;
                        } else {
                            warn!("Rejected connection from {}: No matching Peer Config found (and no dynamic peer configured).", remote_addr);
                            connection.close(0u32.into(), b"No Peer Config Match");
                        }
                    }
                    Err(e) => warn!("Connection handshake failed: {}", e),
                }
            });
        }
    });

    // 3. Outbound Data Loop
    while let Some(cmd) = to_tunnel_rx.recv().await {
        match cmd {
            TunnelCommand::SendData { destination_id, payload } => {
                if let Err(_e) = super::door::send_packet(&destination_id, payload, &peers).await {
                    // Debug log to avoid flooding logs during outages
                    debug!("Failed to send to {}: {}", destination_id, _e);
                }
            }
        }
    }
}