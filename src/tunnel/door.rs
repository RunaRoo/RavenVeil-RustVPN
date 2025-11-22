use super::*;
use crate::crypto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::{trace, warn};
use tokio::sync::mpsc;
use std::sync::Arc;

pub async fn send_packet(
    destination_key: [u8; KEY_SIZE],
    payload: bytes::Bytes,
    peers: &PeerMap,
) -> anyhow::Result<()> {
    let peers_guard = peers.read().await;
    let peer = match peers_guard.get(&destination_key) {
        Some(p) => p.clone(),
        None => return Err(anyhow::anyhow!("Peer not found")),
    };
    drop(peers_guard);

    if !*peer.session_ready_rx.borrow() {
        return Err(anyhow::anyhow!("Session not ready"));
    }

    let mut noise = peer.noise.write().await;
    let kp = noise.current_keypair.as_mut()
        .ok_or_else(|| anyhow::anyhow!("No active keypair"))?;

    let encrypted = crypto::encrypt_packet(&kp.send_key, kp.send_nonce, &payload)?;
    kp.send_nonce += 1;
    drop(noise);

    peer.stats.bytes_sent.fetch_add(encrypted.len() as u64, std::sync::atomic::Ordering::Relaxed);

    let mut stream_guard = peer.send_stream.lock().await;
    if let Some(stream) = stream_guard.as_mut() {
        if encrypted.len() > u16::MAX as usize {
            return Err(anyhow::anyhow!("Packet too large"));
        }
        let len = encrypted.len() as u16;

        stream.write_u16(len).await?;
        stream.write_all(&encrypted).await?;
    } else {
        return Err(anyhow::anyhow!("Stream closed"));
    }

    Ok(())
}

pub async fn spawn_data_processor(
    peer: Arc<Peer>,
    mut recv: quinn::RecvStream,
    tx: mpsc::Sender<TunnelEvent>,
) {
    tokio::spawn(async move {
        loop {
            let len = match recv.read_u16().await {
                Ok(l) => l as usize,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::UnexpectedEof {
                        warn!("Stream read error: {}", e);
                    }
                    break;
                }
            };

            let mut buf = vec![0u8; len];
            if let Err(e) = recv.read_exact(&mut buf).await {
                warn!("Stream failed to read payload of size {}: {}", len, e);
                break;
            }

            let mut noise = peer.noise.write().await;
            match crypto::try_decrypt_with_rotation(&mut noise, &buf) {
                Ok(plain) => {
                    peer.stats.bytes_received.fetch_add(plain.len() as u64, std::sync::atomic::Ordering::Relaxed);

                    if !plain.is_empty() {
                        let _ = tx.send(TunnelEvent::DataReceived {
                            source_key: peer.static_public_key,
                            payload: plain.into()
                        }).await;
                    } else {
                        trace!("Received KeepAlive");
                    }
                }
                Err(e) => {
                    warn!("Decryption failed from peer: {}", e);
                }
            }
        }

        let _ = peer.session_ready_tx.send(false);
    });
}