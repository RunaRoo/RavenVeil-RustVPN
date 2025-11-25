use super::*;
use log::{trace, warn, debug, error};
use tokio::sync::mpsc;
use std::sync::Arc;
use bytes::Bytes;
use sha2::{Sha256, Digest};

/// Calculate a simple hash of the PSK to verify authorization without sending the raw key.
pub(crate) fn hash_psk(psk: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"RavenVeil-PSK-Auth:"); // Salt
    hasher.update(psk.as_bytes());
    hasher.finalize().to_vec()
}

/// Sends a raw IP packet via QUIC Datagrams.
pub async fn send_packet(
    destination_id: &str, // Changed from [u8;32] to String key
    payload: Bytes,
    peers: &PeerMap,
) -> anyhow::Result<()> {
    let peers_guard = peers.read().await;
    let peer = match peers_guard.get(destination_id) {
        Some(p) => p.clone(),
        None => return Err(anyhow::anyhow!("Peer not found")),
    };
    drop(peers_guard);

    if !*peer.session_ready_rx.borrow() {
        return Ok(()); // Drop silently if not ready
    }

    let conn_guard = peer.connection.read().await;
    if let Some(conn) = conn_guard.as_ref() {
        match conn.send_datagram(payload.clone()) {
            Ok(_) => {
                peer.stats.bytes_sent.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                trace!("Datagram dropped: {}", e);
                Ok(())
            }
        }
    } else {
        Err(anyhow::anyhow!("Connection not established"))
    }
}

/// Reads incoming QUIC Datagrams.
///
/// This function also handles the initial "PSK Authorization" if a PSK is configured.
pub async fn spawn_data_processor(
    peer: Arc<Peer>,
    conn: quinn::Connection,
    tx: mpsc::Sender<TunnelEvent>,
) {
    tokio::spawn(async move {
        debug!("Datagram processor started for peer {}", peer.config.public_key);

        // --- PSK CHECK LOGIC ---
        // If a PSK is configured, we expect the FIRST datagram to be the PSK Hash.
        if !peer.config.preshared_key.is_empty() {
            debug!("Waiting for PSK verification...");
            match conn.read_datagram().await {
                Ok(data) => {
                    let expected = hash_psk(&peer.config.preshared_key);
                    if data != expected {
                        error!("PSK Mismatch! Dropping connection.");
                        conn.close(0u32.into(), b"PSK Auth Failed");
                        return;
                    }
                    debug!("PSK Verified.");
                }
                Err(e) => {
                    warn!("Failed to read PSK packet: {}", e);
                    return;
                }
            }
        }

        // --- NORMAL TRAFFIC LOOP ---
        loop {
            match conn.read_datagram().await {
                Ok(data) => {
                    if data.is_empty() {
                        trace!("Received Keepalive");
                        continue;
                    }

                    let packet_len = data.len();
                    peer.stats.bytes_received.fetch_add(packet_len as u64, std::sync::atomic::Ordering::Relaxed);

                    let _ = tx.send(TunnelEvent::DataReceived {
                        source_id: peer.config.public_key.clone(),
                        payload: data,
                    }).await;
                }
                Err(e) => {
                    warn!("Connection lost: {}", e);
                    break;
                }
            }
        }

        let _ = peer.session_ready_tx.send(false);
    });
}