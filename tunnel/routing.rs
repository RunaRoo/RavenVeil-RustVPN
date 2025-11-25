use super::{Peer, PeerMap};
use crate::config::PeerConfig;
use crate::tunnel::stats::{PeerStats, ConnectionQuality};
use anyhow::Result;
use etherparse::{NetSlice, SlicedPacket};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, watch};
use std::str::FromStr;

pub async fn build_peer_map(peer_configs: &[PeerConfig]) -> Result<PeerMap> {
    let mut peers = HashMap::new();

    for peer_config in peer_configs {
        // Resolve endpoint if present
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
            stats: Arc::new(PeerStats::default()),
            endpoint_addr: RwLock::new(endpoint),
            connection: RwLock::new(None),
            session_ready_tx: tx,
            session_ready_rx: rx,
            connection_quality: RwLock::new(ConnectionQuality::default()),
        });

        // Use the public_key field as the unique Identifier (ID)
        peers.insert(peer_config.public_key.clone(), peer);
    }
    Ok(Arc::new(RwLock::new(peers)))
}

pub async fn find_route_for_packet(
    packet: &[u8],
    routing_table: &Arc<RwLock<Vec<(ipnetwork::IpNetwork, String)>>>,
) -> Option<String> {
    let dest_addr = match SlicedPacket::from_ip(packet) {
        Ok(SlicedPacket { net: Some(NetSlice::Ipv4(ipv4)), .. }) =>
            Some(IpAddr::V4(ipv4.header().destination_addr())),
        Ok(SlicedPacket { net: Some(NetSlice::Ipv6(ipv6)), .. }) =>
            Some(IpAddr::V6(ipv6.header().destination_addr())),
        _ => None,
    }?;

    let table = routing_table.read().await;
    table.iter()
        .find(|(net, _)| net.contains(dest_addr))
        .map(|(_, id)| id.clone())
}