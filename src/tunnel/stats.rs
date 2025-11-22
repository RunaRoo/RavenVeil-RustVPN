use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Debug, Default)]
pub struct PeerStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub last_handshake: RwLock<Option<Instant>>,
}

#[derive(Debug, Clone)]
pub struct ConnectionQuality {
    pub latency: std::time::Duration,
    pub packet_loss: f32,
    pub last_lost_packets: u64,
    pub last_sent_packets: u64,
}

impl Default for ConnectionQuality {
    fn default() -> Self {
        Self {
            latency: std::time::Duration::from_millis(0),
            packet_loss: 0.0,
            last_lost_packets: 0,
            last_sent_packets: 0,
        }
    }
}