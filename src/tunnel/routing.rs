use super::{Peer, PeerMap};
use crate::config::PeerConfig;
use crate::crypto::{NoiseState, KEY_SIZE};
use crate::tunnel::stats::{PeerStats, ConnectionQuality};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use etherparse::{NetSlice, SlicedPacket};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, watch};

pub async fn build_peer_map(peer_configs: &[PeerConfig]) -> Result<PeerMap> {
    let mut peers = HashMap::new();
    for peer_config in peer_configs {
        let pub_key_bytes = B64.decode(&peer_config.public_key)?;
        let pub_key: [u8; KEY_SIZE] = pub_key_bytes.as_slice().try_into()?;

        let endpoint = if !peer_config.endpoint.is_empty() {
            match tokio::net::lookup_host(&peer_config.endpoint).await?.next() {
                Some(addr) => Some(addr),
                None => return Err(anyhow::anyhow!("Could not resolve endpoint: {}", &peer_config.endpoint)),
            }
        } else {
            None
        };

        let (tx, rx) = watch::channel(false);

        let peer = Arc::new(Peer {
            config: peer_config.clone(),
            noise: Arc::new(RwLock::new(NoiseState::new())),
            stats: Arc::new(PeerStats::default()),
            endpoint_addr: RwLock::new(endpoint),
            connection: RwLock::new(None),
            send_stream: Mutex::new(None),
            session_ready_tx: tx,
            session_ready_rx: rx,
            static_public_key: pub_key,
            handshake_lock: Mutex::new(()),
            connection_quality: RwLock::new(ConnectionQuality::default()),
        });
        peers.insert(pub_key, peer);
    }
    Ok(Arc::new(RwLock::new(peers)))
}

pub async fn find_route_for_packet(
    packet: &[u8],
    routing_table: &Arc<RwLock<Vec<(ipnetwork::IpNetwork, [u8; 32])>>>,
) -> Option<[u8; 32]> {
    let dest_addr = match SlicedPacket::from_ip(packet) {
        Ok(SlicedPacket { net: Some(NetSlice::Ipv4(ipv4)), .. }) =>
            Some(IpAddr::V4(ipv4.header().destination_addr())),
        Ok(SlicedPacket { net: Some(NetSlice::Ipv6(ipv6)), .. }) =>
            Some(IpAddr::V6(ipv6.header().destination_addr())),
        _ => None,
    }?;

    routing_table.read().await.iter()
        .find(|(net, _)| net.contains(dest_addr))
        .map(|(_, key)| *key)
}