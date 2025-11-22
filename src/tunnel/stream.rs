use super::*;
use anyhow::Result;
use std::sync::Arc;
use tokio::time::Duration;
use log::{info, warn};
use crate::config::Config;
use crate::tunnel::util::load_our_static_key;
use tokio::sync::mpsc;

pub async fn manage_peer_connection(
    peer: Arc<Peer>,
    config: Arc<Config>,
    client_endpoint: quinn::Endpoint,
    from_tunnel_tx: mpsc::Sender<TunnelEvent>,
) -> Result<()> {
    let our_static = load_our_static_key(&config)?;

    // Start maintenance tasks
    super::rekey::spawn_rekey_task(peer.clone(), config.clone(), from_tunnel_tx.clone()).await;
    super::keepalive::spawn_keepalive_task(peer.clone()).await;

    loop {
        if peer.config.endpoint.is_empty() {
            // Passive mode (Server)
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        // Active mode (Client)
        let remote = match peer.endpoint_addr.read().await.clone() {
            Some(addr) => addr,
            None => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        // Attempt Connect
        match client_endpoint.connect(remote, "localhost") {
            Ok(connecting) => {
                match connecting.await {
                    Ok(conn) => {
                        info!("QUIC Connected to {}", remote);
                        *peer.connection.write().await = Some(conn);

                        // Initiate Handshake
                        if let Err(e) = super::handshake::perform_client_handshake(
                            peer.clone(),
                            &our_static,
                            from_tunnel_tx.clone()
                        ).await {
                            warn!("Handshake failed: {}", e);
                        }

                        // Watch session status
                        let mut rx = peer.session_ready_rx.clone();
                        while rx.changed().await.is_ok() {
                            if !*rx.borrow() {
                                info!("Session closed/rekey requested for {}", remote);
                                break;
                            }
                        }
                    },
                    Err(e) => {
                        warn!("Connection failure to {}: {}", remote, e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            },
            Err(e) => {
                warn!("Endpoint connect error: {}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}