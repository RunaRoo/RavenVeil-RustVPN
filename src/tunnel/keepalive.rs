use super::*;
use std::time::Duration;
use bytes::Bytes;
use log::trace;
//use tokio::io::AsyncWriteExt;

pub async fn spawn_keepalive_task(peer: Arc<Peer>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;

            if !*peer.session_ready_rx.borrow() {
                continue;
            }

            let empty = Bytes::new();

            // We manually encrypt and send here to avoid deadlock complexity with the main door
            // and to be efficient.
            let mut noise = peer.noise.write().await;
            if let Some(kp) = noise.current_keypair.as_mut() {
                if let Ok(enc) = crate::crypto::encrypt_packet(&kp.send_key, kp.send_nonce, &empty) {
                    kp.send_nonce += 1;
                    // Drop lock before awaiting IO
                    drop(noise);

                    let mut stream_guard = peer.send_stream.lock().await;
                    if let Some(s) = stream_guard.as_mut() {
                        if let Err(e) = s.write_all(&enc).await {
                            trace!("Keepalive failed: {}", e);
                        }
                    }
                }
            }
        }
    });
}