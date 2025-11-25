use crate::app_config::AppConfig;
use crate::config::Config;
use super::TUN;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::{info, warn};
use std::mem::ManuallyDrop;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::io::AsRawFd;
use tokio::io::unix::AsyncFd;
use tun::Device;

pub struct TUNDevice {
    iface: Arc<Mutex<AsyncFd<tun::platform::Device>>>,
    name: String,
    config: Arc<Config>,
    dns_service: Option<String>,
}

#[async_trait]
impl TUN for TUNDevice {
    async fn create(
        name: &str,
        config: Arc<Config>,
        _app_config: Arc<AppConfig>,
    ) -> Result<Box<dyn TUN>> {
        info!("Creating macOS TUN device '{}'", name);

        let mut tun_config = tun::Configuration::default();
        tun_config
            .layer(tun::Layer::L3)
            .name(name)
            .up();

        let device = tun::create(&tun_config)
            .map_err(|e| anyhow!("Failed to create TUN device: {}", e))?;

        // Set non-blocking mode using socket2 to avoid unsafe libc calls
        let raw_fd = device.as_raw_fd();
        let socket = unsafe { socket2::Socket::from_raw_fd(raw_fd) };
        socket.set_nonblocking(true)?;
        // IMPORTANT: We must forget the socket, otherwise it closes the FD when dropped!
        std::mem::forget(socket);

        let async_device = AsyncFd::new(device)?;

        // Handle the Result returned by name()
        let actual_name = async_device.get_ref().name()
            .map_err(|e| anyhow!("Failed to get TUN name: {}", e))?;

        info!("TUN device created: {}", actual_name);

        // Set MTU
        run_cmd(&format!("ifconfig {} mtu {}", actual_name, config.interface.mtu))?;

        // Assign IP addresses
        for addr in &config.interface.addresses {
            run_cmd(&format!("ifconfig {} {} {} up", actual_name, addr, addr))?;
        }

        // Add routes
        for peer in &config.peers {
            for cidr in peer.allowed_ips.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                if let Err(e) = run_cmd(&format!("route add -net {} -interface {}", cidr, actual_name)) {
                    warn!("Failed to add route {}: {}", cidr, e);
                }
            }
        }

        // DNS configuration
        let mut dns_service = None;
        if !config.interface.dns.is_empty() {
            match configure_dns(&config.interface.dns) {
                Ok(service) => {
                    info!("DNS configured on service: {}", service);
                    dns_service = Some(service);
                }
                Err(e) => warn!("Failed to set DNS: {}", e),
            }
        }

        // PostUp script
        if !config.interface.post_up.is_empty() {
            let cmd = config.interface.post_up.replace("%i", &actual_name);
            info!("Running PostUp: {}", cmd);
            let _ = run_cmd(&cmd);
        }

        info!("macOS TUN interface '{}' is ready", actual_name);

        Ok(Box::new(Self {
            iface: Arc::new(Mutex::new(async_device)),
            name: actual_name,
            config,
            dns_service,
        }))
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.iface.lock().await;
        // Capture the raw FD so we can use it inside the closure without borrowing guard
        let fd = guard.as_raw_fd();

        loop {
            let mut ready_guard = guard.writable().await?;

            // Use try_io with socket2 to write to the FD.
            // socket2 implementations of Read/Write work on '&Socket' (immutable),
            // which solves the borrowing conflict.
            match ready_guard.try_io(|_inner| {
                let socket = unsafe { socket2::Socket::from_raw_fd(fd) };
                let socket = ManuallyDrop::new(socket);
                (&*socket).write(buf)
            }) {
                Ok(result) => return result.map_err(|e| anyhow!(e)),
                Err(_would_block) => continue, // try_io handles clearing readiness
            }
        }
    }

    async fn read(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.config.interface.mtu as usize + 512];
        let mut guard = self.iface.lock().await;
        let fd = guard.as_raw_fd();

        loop {
            let mut ready_guard = guard.readable().await?;

            match ready_guard.try_io(|_inner| {
                let socket = unsafe { socket2::Socket::from_raw_fd(fd) };
                let socket = ManuallyDrop::new(socket);
                (&*socket).read(&mut buf)
            }) {
                Ok(result) => {
                    let n = result.map_err(|e| anyhow!(e))?;
                    buf.truncate(n);
                    return Ok(buf);
                },
                Err(_would_block) => continue,
            }
        }
    }

    async fn try_clone(&self) -> Result<Box<dyn TUN>> {
        Ok(Box::new(Self {
            iface: self.iface.clone(),
            name: self.name.clone(),
            config: self.config.clone(),
            dns_service: self.dns_service.clone(),
        }))
    }
}

impl Drop for TUNDevice {
    fn drop(&mut self) {
        info!("Cleaning up TUN device '{}'", self.name);

        if let Some(service) = &self.dns_service {
            let _ = restore_dns(service);
        }

        if !self.config.interface.post_down.is_empty() {
            let cmd = self.config.interface.post_down.replace("%i", &self.name);
            let _ = run_cmd(&cmd);
        }
    }
}

// --- Helper Functions ---

fn get_primary_service() -> Result<String> {
    let output = Command::new("networksetup")
        .arg("-listnetworkserviceorder")
        .output()?;
    let output = String::from_utf8_lossy(&output.stdout);

    for line in output.lines() {
        if line.contains("(Hardware Port:") {
            if let Some(service) = line.split(':').nth(1).map(|s| s.trim().trim_matches('"')) {
                if service.contains("Wi-Fi") || service.contains("Ethernet") || service.contains("Thunderbolt") {
                    return Ok(service.to_string());
                }
            }
        }
    }
    Err(anyhow!("No active network service found"))
}

fn configure_dns(dns_servers: &str) -> Result<String> {
    let service = get_primary_service()?;
    let servers = dns_servers.replace(',', " ");
    run_cmd(&format!("networksetup -setdnsservers \"{}\" {}", service, servers))?;
    Ok(service)
}

fn restore_dns(service: &str) -> Result<()> {
    run_cmd(&format!("networksetup -setdnsservers \"{}\" empty", service))
        .map_err(|e| {
            warn!("Failed to restore DNS: {}", e);
            e
        })
}

fn run_cmd(cmd: &str) -> Result<()> {
    info!("Running: {}", cmd);
    let output = Command::new("sh").arg("-c").arg(cmd).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Command failed: {}\n{}", cmd, stderr));
    }
    Ok(())
}