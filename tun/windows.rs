//! tun/windows.rs - Windows TUN implementation using wintun
use crate::app_config::AppConfig;
use crate::config::Config;
use crate::tun::TUN;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::{info, warn};
use std::sync::Arc;
use tokio::net::lookup_host;
use wintun::Session;

pub struct TUNDevice {
    session: Arc<Session>,
    name: String,
    config: Arc<Config>,
}

#[async_trait]
impl TUN for TUNDevice {
    async fn create(
        name: &str,
        config: Arc<Config>,
        _app_config: Arc<AppConfig>,
    ) -> Result<Box<dyn TUN>> {
        info!("Creating Windows TUN device using wintun");

        let wintun =
            unsafe { wintun::load() }.map_err(|e| anyhow!("Failed to load wintun.dll: {}", e))?;

        let delete_cmd = format!("netsh interface delete interface \"{}\"", name);
        info!("Attempting to clean up previous adapter with command: '{}'", delete_cmd);
        let _ = run_cmd(&delete_cmd);

        let adapter = wintun::Adapter::create(&wintun, name, name, None)
            .map_err(|e| anyhow!("Failed to create adapter: {}", e))?;

        let session = match adapter.start_session(wintun::MAX_RING_CAPACITY) {
            Ok(session) => Arc::new(session),
            Err(e) => {
                let _ = run_cmd(&delete_cmd);
                return Err(anyhow!("Failed to start wintun session: {}", e));
            }
        };

        let interface_address = config.interface.addresses.get(0)
            .ok_or_else(|| anyhow!("No address configured for the interface"))?;

        info!("Setting IP address {} on interface '{}'", interface_address, name);
        let ip_cmd = format!("netsh interface ip set address name=\"{}\" static {}", name, interface_address);
        if let Err(e) = run_cmd(&ip_cmd) {
            let _ = run_cmd(&delete_cmd); // Cleanup on failure
            return Err(anyhow!("Failed to set IP address on TUN device: {}. Make sure you are running as Administrator.", e));
        }

        // Configure DNS using netsh
        if !config.interface.dns.is_empty() {
            let clear_dns_cmd = format!("netsh interface ip set dnsservers name=\"{}\" static none", name);
            if let Err(e) = run_cmd(&clear_dns_cmd) { warn!("Could not clear existing DNS settings: {}", e); }

            for (i, server) in config.interface.dns.split(',').enumerate() {
                let server = server.trim();
                if server.is_empty() { continue; }
                let dns_cmd = format!("netsh interface ip add dnsserver name=\"{}\" address={} index={}", name, server, i + 1);
                info!("Setting DNS with command: '{}'", dns_cmd);
                if let Err(e) = run_cmd(&dns_cmd) {
                    warn!("Failed to set DNS: {}", e);
                }
            }
        }

        if let Err(e) = configure_windows_routes(&config, name).await {
            warn!("Failed to configure Windows routes automatically: {}. You may need to add them manually.", e);
            // Do not return Err here to allow app to run even if some routes fail (e.g. ipv6 disabled)
        }

        if !config.interface.post_up.is_empty() {
            let cmd_to_run = config.interface.post_up.replace("%i", name);
            info!("Running PostUp command: {}", cmd_to_run);
            if let Err(e) = run_cmd(&cmd_to_run) {
                warn!("PostUp command failed: {}", e);
            }
        }

        Ok(Box::new(TUNDevice {
            session,
            name: name.to_string(),
            config,
        }))
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut packet = self.session.allocate_send_packet(buf.len() as u16)
            .map_err(|_| anyhow!("Failed to allocate send packet"))?;
        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);
        Ok(buf.len())
    }

    async fn read(&self) -> Result<Vec<u8>> {
        let packet = self.session.receive_blocking()
            .map_err(|e| anyhow!("Failed to receive packet: {}", e))?;
        Ok(packet.bytes().to_vec())
    }

    async fn try_clone(&self) -> Result<Box<dyn TUN>> {
        Ok(Box::new(TUNDevice {
            session: self.session.clone(),
            name: self.name.clone(),
            config: self.config.clone(),
        }))
    }
}

async fn configure_windows_routes(config: &Arc<Config>, interface_name: &str) -> Result<()> {
    let peer_with_endpoint = match config.peers.iter().find(|p| !p.endpoint.is_empty()) {
        Some(peer) => peer,
        None => {
            info!("No peer with an endpoint is configured. Assuming server-only mode. No routes will be added.");
            return Ok(());
        }
    };

    let peer_addr = lookup_host(&peer_with_endpoint.endpoint).await?.next()
        .ok_or_else(|| anyhow!("Could not resolve peer endpoint: {}", &peer_with_endpoint.endpoint))?.ip();

    info!("Resolved peer endpoint {} to {}", &peer_with_endpoint.endpoint, peer_addr);

    // Add specific route for the VPN server so we don't loop
    let add_peer_route_cmd = if peer_addr.is_ipv6() {
        format!("netsh interface ipv6 add route {}/128 \"{}\" metric=10", peer_addr, interface_name)
    } else {
        // classic route command is often more reliable for specific host routes
        format!("route ADD {} MASK 255.255.255.255 0.0.0.0 METRIC 10", peer_addr)
    };

    info!("Adding specific route for peer {} via default gateway", peer_addr);
    if let Err(e) = run_cmd(&add_peer_route_cmd) {
        return Err(anyhow!("Failed to add specific route for the peer: {}", e));
    }

    for cidr in peer_with_endpoint.allowed_ips.split(',') {
        let cidr = cidr.trim();
        if cidr.is_empty() { continue; }

        info!("Adding VPN route for {} with a low metric", cidr);

        // DETECT IPV6 to prevent crashes
        let is_ipv6 = cidr.contains(':');
        let add_vpn_route_cmd = if is_ipv6 {
            format!("netsh interface ipv6 add route {} \"{}\" :: metric=5", cidr, interface_name)
        } else {
            format!("netsh interface ip add route {} \"{}\" 0.0.0.0 metric=5", cidr, interface_name)
        };

        if let Err(e) = run_cmd(&add_vpn_route_cmd) {
            // If IPv6 fails, it might just be disabled on the adapter. Warn instead of crash.
            if is_ipv6 {
                warn!("Failed to add IPv6 route (IPv6 might be disabled): {}", e);
            } else {
                let cleanup_cmd = format!("route DELETE {}", peer_addr);
                let _ = run_cmd(&cleanup_cmd);
                return Err(anyhow!("Failed to set the default route for the VPN interface: {}", e));
            }
        }
    }

    Ok(())
}

impl Drop for TUNDevice {
    fn drop(&mut self) {
        info!("Cleaning up TUN device '{}'", self.name);

        if !self.config.interface.post_down.is_empty() {
            let cmd_to_run = self.config.interface.post_down.replace("%i", &self.name);
            info!("Running PostDown command: {}", cmd_to_run);
            if let Err(e) = run_cmd(&cmd_to_run) { warn!("PostDown command failed: {}", e); }
        }

        let delete_cmd = format!("netsh interface delete interface \"{}\"", self.name);
        info!("Deleting interface with command: '{}'", delete_cmd);
        if let Err(e) = run_cmd(&delete_cmd) {
            warn!("Failed to delete interface '{}': {}", self.name, e);
        }
    }
}

fn run_cmd(cmd: &str) -> Result<()> {
    let output = std::process::Command::new("cmd").args(["/C", cmd]).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("not found") && !stderr.contains("does not exist") && !stderr.contains("already exists") {
            return Err(anyhow!("Command '{}' failed: {}", cmd, stderr));
        }
    }
    Ok(())
}