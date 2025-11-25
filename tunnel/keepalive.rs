use super::*;
use std::time::Duration;
use bytes::Bytes;
use log::trace;

pub async fn spawn_keepalive_task(peer: Arc<Peer>) {
    tokio::spawn(async move {
        // Keepalive interval
        let mut interval = tokio::time::interval(Duration::from_secs(20));
        loop {
            interval.tick().await;

            if !*peer.session_ready_rx.borrow() {
                continue;
            }

            let conn_guard = peer.connection.read().await;
            if let Some(conn) = conn_guard.as_ref() {
                // FIX: Send empty DATAGRAM, no encryption logic needed here (TLS handles it)
                if let Err(e) = conn.send_datagram(Bytes::new()) {
                    trace!("Keepalive failed: {}", e);
                }
            }
        }
    });
}