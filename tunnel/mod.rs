pub mod door;
pub mod keepalive;
// pub mod rekey; // REMOVED: TLS 1.3 handles rekeying automatically
pub mod routing;
pub mod stats;
pub mod stream;
pub mod util;
pub mod waveguider;

// Re-exports for external usage
pub use waveguider::{run_tunnel, TunnelHandle};
pub use routing::find_route_for_packet;

use crate::config::PeerConfig;
use crate::tunnel::stats::{PeerStats, ConnectionQuality};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, watch};
use std::collections::HashMap;
use bytes::Bytes;

// Internal Shared Types

#[derive(Debug)]
pub enum TunnelCommand {
    // We use String IDs now (e.g. "peer-1" or hostname), not [u8;32] keys
    SendData { destination_id: String, payload: Bytes },
}

#[derive(Debug)]
pub enum TunnelEvent {
    // We use String IDs now
    DataReceived { source_id: String, payload: Bytes },
}

#[derive(Debug)]
pub struct Peer {
    pub config: PeerConfig,
    pub stats: Arc<PeerStats>,
    pub endpoint_addr: RwLock<Option<std::net::SocketAddr>>,
    pub connection: RwLock<Option<quinn::Connection>>,
    pub session_ready_tx: watch::Sender<bool>,
    pub session_ready_rx: watch::Receiver<bool>,
    pub connection_quality: RwLock<ConnectionQuality>,
}

pub type PeerMap = Arc<RwLock<HashMap<String, Arc<Peer>>>>;