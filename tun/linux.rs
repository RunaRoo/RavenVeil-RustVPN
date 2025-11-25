use crate::app_config::AppConfig;
use crate::config::Config;
use super::TUN;
use anyhow::{anyhow, Result, Context};
use async_trait::async_trait;
use log::{info, warn};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_tun::Tun;

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
const RESOLV_CONF_BACKUP_PATH: &str = "/etc/resolv.conf.ravenveil.bak";

pub struct TUNDevice {
    iface: Arc<Mutex<Tun>>,
    name: String,
    config: Arc<Config>,
    dns_configured: bool,
}

#[async_trait]
impl TUN for TUNDevice {
    async fn create(
        name: &str,
        config: Arc<Config>,
        _app_config: Arc<AppConfig>,
    ) -> Result<Box<dyn TUN>> {
        info!("Creating Linux TUN device '{}'", name);

        // --- FIXED: Handle Vec<Tun> return type ---
        // The .build() method returns a Vec<Tun> (for multi-queue support).
        // We use .pop() to get the single interface instance we need.
        let tun = Tun::builder()
            .name(name)
            .up()
            .build()
            .map_err(|e| anyhow!("Failed to build TUN device: {}", e))?
            .pop()
            .ok_or(anyhow!("TUN builder returned no file descriptors"))?;

        let mtu = config.interface.mtu;
        run_cmd(&format!("ip link set dev {} mtu {}", name, mtu))?;
        for addr in &config.interface.addresses {
            run_cmd(&format!("ip addr add {} dev {}", addr, name))?;
        }
        for peer in &config.peers {
            for cidr in peer.allowed_ips.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                if let Err(e) = run_cmd(&format!("ip route add {} dev {}", cidr, name)) {
                    warn!("Failed to add route for {}: {}", cidr, e);
                }
            }
        }

        let mut dns_configured = false;
        if !config.interface.dns.is_empty() {
            info!("Configuring system DNS. This requires root privileges and may not work with systemd-resolved.");
            if let Err(e) = configure_linux_dns(&config.interface.dns) {
                warn!("Failed to configure system DNS: {}. DNS queries may leak.", e);
            } else {
                info!("System DNS configured to use: {}", &config.interface.dns);
                dns_configured = true;
            }
        }

        if !config.interface.post_up.is_empty() {
            let cmd = config.interface.post_up.replace("%i", name);
            info!("Running PostUp command: {}", &cmd);
            if let Err(e) = run_cmd(&cmd) {
                warn!("PostUp command failed: {}", e);
            }
        }

        info!("TUN device '{}' is up and configured.", name);

        Ok(Box::new(Self {
            iface: Arc::new(Mutex::new(tun)),
            name: name.to_string(),
            config,
            dns_configured,
        }))
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn write(&self, buf: &[u8]) -> Result<usize> {
        self.iface.lock().await.write(buf).await.map_err(Into::into)
    }

    async fn read(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; (self.config.interface.mtu + 512) as usize];
        let n = self.iface.lock().await.read(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn try_clone(&self) -> Result<Box<dyn TUN>> {
        Ok(Box::new(Self {
            iface: self.iface.clone(),
            name: self.name.clone(),
            config: self.config.clone(),
            dns_configured: self.dns_configured,
        }))
    }
}

impl Drop for TUNDevice {
    fn drop(&mut self) {
        info!("Cleaning up TUN device '{}'", self.name);

        if self.dns_configured {
            if let Err(e) = restore_linux_dns() {
                warn!("Failed to restore original DNS settings: {}", e);
            } else {
                info!("Original DNS settings restored.");
            }
        }

        if !self.config.interface.post_down.is_empty() {
            let cmd = self.config.interface.post_down.replace("%i", &self.name);
            info!("Running PostDown command: {}", &cmd);
            if let Err(e) = run_cmd(&cmd) {
                warn!("PostDown command failed: {}", e);
            }
        }
    }
}

fn configure_linux_dns(dns_servers: &str) -> Result<()> {
    if Path::new(RESOLV_CONF_BACKUP_PATH).exists() {
        warn!("DNS backup file already exists. Another instance may be running or the previous one crashed.");
    } else {
        fs::copy(RESOLV_CONF_PATH, RESOLV_CONF_BACKUP_PATH)
            .context("Failed to back up /etc/resolv.conf")?;
    }

    let new_content: String = dns_servers
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| format!("nameserver {}", s))
        .collect::<Vec<_>>()
        .join("\n");

    fs::write(RESOLV_CONF_PATH, new_content)
        .context("Failed to write new /etc/resolv.conf")?;
    Ok(())
}

fn restore_linux_dns() -> Result<()> {
    if Path::new(RESOLV_CONF_BACKUP_PATH).exists() {
        fs::rename(RESOLV_CONF_BACKUP_PATH, RESOLV_CONF_PATH)
            .context("Failed to restore /etc/resolv.conf from backup")?;
    }
    Ok(())
}

fn run_cmd(cmd: &str) -> Result<()> {
    // FIX: Use 'sh -c' to allow multiple commands separated by semicolons
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Command '{}' failed: {}", cmd, stderr));
    }
    Ok(())
}