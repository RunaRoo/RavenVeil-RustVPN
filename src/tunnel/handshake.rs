use super::*;
use crate::crypto;
use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use log::info;
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};
use tokio::sync::mpsc;
use std::time::Instant;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

// Packet Layouts:
const HANDSHAKE_INIT_SIZE: usize = 1 + 32 + 32;
const HANDSHAKE_RESP_SIZE: usize = 1 + 32;

/// Client Side: Initiates the handshake
pub async fn perform_client_handshake(
    peer: Arc<Peer>,
    our_static: &StaticSecret,
    from_tunnel_tx: mpsc::Sender<TunnelEvent>,
) -> Result<()> {
    let conn_guard = peer.connection.read().await;
    let conn = conn_guard.as_ref().ok_or_else(|| anyhow!("No QUIC connection established"))?.clone();
    drop(conn_guard);

    let (mut send, mut recv) = conn.open_bi().await?;

    let our_eph = ReusableSecret::random_from_rng(OsRng);
    let our_eph_pub = PublicKey::from(&our_eph);
    let our_static_pub = PublicKey::from(our_static);
    let their_static_pub = PublicKey::from(peer.static_public_key);

    let psk = crypto::decode_psk(&peer.config.preshared_key)?;

    // 1. Construct Handshake Initiation
    let mut init_msg = BytesMut::with_capacity(HANDSHAKE_INIT_SIZE);
    init_msg.put_u8(1); // Type: Init
    init_msg.put_slice(our_static_pub.as_bytes()); // Identify ourselves
    init_msg.put_slice(our_eph_pub.as_bytes());    // Our ephemeral

    send.write_all(&init_msg).await?;

    // 2. Wait for Response
    let mut resp_buf = [0u8; HANDSHAKE_RESP_SIZE];
    recv.read_exact(&mut resp_buf).await?;

    if resp_buf[0] != 2 {
        return Err(anyhow!("Invalid handshake response type"));
    }

    // 3. Derive Keys
    let their_eph_bytes: [u8; 32] = resp_buf[1..33].try_into()?;
    let their_eph_pub = PublicKey::from(their_eph_bytes);

    let (send_key, recv_key) = crypto::derive_keys(
        our_static,
        &our_eph,
        &their_static_pub, // We know who we are talking to
        &their_eph_pub,
        &psk,
        true, // is_initiator
        None
    )?;

    // 4. Update State
    {
        let mut noise = peer.noise.write().await;
        noise.previous_keypair = noise.current_keypair.take();
        noise.current_keypair = Some(crypto::Keypair::new(send_key, recv_key));
    }

    peer.stats.last_handshake.write().await.replace(Instant::now());

    // 5. Start Receiving Data on this stream
    super::door::spawn_data_processor(peer.clone(), recv, from_tunnel_tx).await;

    *peer.send_stream.lock().await = Some(send);

    let _ = peer.session_ready_tx.send(true);
    info!("Client Handshake completed with peer {}", B64.encode(peer.static_public_key));

    Ok(())
}

/// Server Side: Handles an incoming handshake request
pub async fn handle_incoming_handshake(
    stream: (quinn::SendStream, quinn::RecvStream),
    our_static: &StaticSecret,
    peers: PeerMap,
    from_tunnel_tx: mpsc::Sender<TunnelEvent>,
) -> Result<()> {
    let (mut send, mut recv) = stream;

    // 1. Read Init
    let mut init_buf = [0u8; HANDSHAKE_INIT_SIZE];
    recv.read_exact(&mut init_buf).await?;

    if init_buf[0] != 1 {
        return Err(anyhow!("Invalid handshake init type"));
    }

    let sender_static_bytes: [u8; 32] = init_buf[1..33].try_into()?;
    let sender_eph_bytes: [u8; 32] = init_buf[33..65].try_into()?;

    // 2. Identify Peer
    let peers_guard = peers.read().await;
    let peer = peers_guard.get(&sender_static_bytes)
        .ok_or_else(|| anyhow!("Unknown peer public key"))?
        .clone();
    drop(peers_guard);

    // 3. Generate Ephemeral & Derive Keys
    let our_eph = ReusableSecret::random_from_rng(OsRng);
    let our_eph_pub = PublicKey::from(&our_eph);

    let their_static_pub = PublicKey::from(sender_static_bytes);
    let their_eph_pub = PublicKey::from(sender_eph_bytes);

    let psk = crypto::decode_psk(&peer.config.preshared_key)?;

    let (send_key, recv_key) = crypto::derive_keys(
        our_static,
        &our_eph,
        &their_static_pub,
        &their_eph_pub,
        &psk,
        false,
        None
    )?;

    // 4. Send Response
    let mut resp_msg = BytesMut::with_capacity(HANDSHAKE_RESP_SIZE);
    resp_msg.put_u8(2); // Type: Response
    resp_msg.put_slice(our_eph_pub.as_bytes());
    send.write_all(&resp_msg).await?;

    // 5. Update State
    {
        let mut noise = peer.noise.write().await;
        noise.previous_keypair = noise.current_keypair.take();
        noise.current_keypair = Some(crypto::Keypair::new(send_key, recv_key));
    }

    peer.stats.last_handshake.write().await.replace(Instant::now());

    super::door::spawn_data_processor(peer.clone(), recv, from_tunnel_tx).await;

    *peer.send_stream.lock().await = Some(send);

    let _ = peer.session_ready_tx.send(true);
    info!("Server Handshake accepted from peer {}", B64.encode(sender_static_bytes));

    Ok(())
}