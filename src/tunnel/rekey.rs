use super::*;
use crate::tunnel::util::load_our_static_key;
use crate::config::Config;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use log::{info, error};
use base64::Engine;

pub async fn spawn_rekey_task(
    peer: Arc<Peer>,
    config: Arc<Config>,
    to_tunnel_tx: mpsc::Sender<TunnelEvent>,
) {
    let rekey_minutes = config.interface.rekey_after_minutes;
    if rekey_minutes == 0 { return; }

    let our_static = match load_our_static_key(&config) {
        Ok(k) => k,
        Err(e) => {
            error!("Rekey task failed to load private key: {}", e);
            return;
        }
    };

    let mut interval = tokio::time::interval(Duration::from_secs(rekey_minutes * 60));

    tokio::spawn(async move {
        interval.tick().await;

        loop {
            interval.tick().await;
            info!("Initiating Rekey for peer {}", base64::engine::general_purpose::STANDARD.encode(peer.static_public_key));

            match super::handshake::perform_client_handshake(
                peer.clone(),
                &our_static,
                to_tunnel_tx.clone()
            ).await {
                Ok(_) => info!("Rekey successful."),
                Err(e) => error!("Rekey failed: {}", e),
            }
        }
    });
}