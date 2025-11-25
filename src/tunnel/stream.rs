use super::*;
use anyhow::Result;
use std::sync::Arc;
use tokio::time::Duration;
use log::{info, warn};
use tokio::sync::mpsc;
use crate::tunnel::door::hash_psk;

pub async fn manage_peer_connection(
    peer: Arc<Peer>,
    client_endpoint: quinn::Endpoint,
    from_tunnel_tx: mpsc::Sender<TunnelEvent>,
) -> Result<()> {
    // Keepalive is strictly for sending empty frames now
    super::keepalive::spawn_keepalive_task(peer.clone()).await;

    loop {
        if peer.config.endpoint.is_empty() {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let remote = match peer.endpoint_addr.read().await.clone() {
            Some(addr) => addr,
            None => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let server_name = peer.config.endpoint.rsplit_once(':')
            .map(|(host, _)| host.trim_start_matches('[').trim_end_matches(']'))
            .unwrap_or("localhost");

        match client_endpoint.connect(remote, server_name) {
            Ok(connecting) => {
                match connecting.await {
                    Ok(conn) => {
                        info!("QUIC Connected to {}", remote);

                        // --- SEND PSK HASH (If configured) ---
                        if !peer.config.preshared_key.is_empty() {
                            let hash = hash_psk(&peer.config.preshared_key);
                            if let Err(e) = conn.send_datagram(hash.into()) {
                                warn!("Failed to send PSK Auth: {}", e);
                                conn.close(0u32.into(), b"PSK Send Failed");
                                continue;
                            }
                        }

                        *peer.connection.write().await = Some(conn.clone());
                        let _ = peer.session_ready_tx.send(true);

                        // Start reading
                        super::door::spawn_data_processor(peer.clone(), conn, from_tunnel_tx.clone()).await;

                        // Wait for session end
                        let mut rx = peer.session_ready_rx.clone();
                        while rx.changed().await.is_ok() {
                            if !*rx.borrow() {
                                break;
                            }
                        }
                    },
                    Err(e) => {
                        warn!("Connection failure: {}", e);
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