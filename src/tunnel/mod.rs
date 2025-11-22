pub mod door;
pub mod handshake;
pub mod keepalive;
pub mod rekey;
pub mod routing;
pub mod stats;
pub mod stream;
pub mod util;
pub mod waveguider;

// Re-exports for external usage
pub use waveguider::{run_tunnel, TunnelHandle};
pub use routing::find_route_for_packet;

use crate::config::PeerConfig;
use crate::crypto::{NoiseState, KEY_SIZE};
use crate::tunnel::stats::{PeerStats, ConnectionQuality};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, watch};
use std::collections::HashMap;
use bytes::Bytes;

// Internal Shared Types
#[derive(Debug)]
pub enum TunnelCommand {
    SendData { destination_key: [u8; 32], payload: Bytes },
}

#[derive(Debug)]
pub enum TunnelEvent {
    DataReceived { source_key: [u8; 32], payload: Bytes },
}

#[derive(Debug)]
pub struct Peer {
    pub config: PeerConfig,
    pub noise: Arc<RwLock<NoiseState>>,
    pub stats: Arc<PeerStats>,
    pub endpoint_addr: RwLock<Option<std::net::SocketAddr>>,
    pub connection: RwLock<Option<quinn::Connection>>,
    pub send_stream: Mutex<Option<quinn::SendStream>>,
    pub session_ready_tx: watch::Sender<bool>,
    pub session_ready_rx: watch::Receiver<bool>,
    pub static_public_key: [u8; KEY_SIZE],
    pub handshake_lock: Mutex<()>,
    pub connection_quality: RwLock<ConnectionQuality>,
}

pub type PeerMap = Arc<RwLock<HashMap<[u8; 32], Arc<Peer>>>>;