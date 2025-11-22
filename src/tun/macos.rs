use crate::app_config::AppConfig;
use crate::config::Config;
use super::TUN;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use log::{info, warn};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_tun::Tun;

pub struct TUNDevice {
    iface: Arc<Mutex<Tun>>,
    name: String,
    config: Arc<Config>,
    dns_configured_service: Option<String>,
}

#[async_trait]
impl TUN for TUNDevice {
    async fn create(
        name: &str,
        config: Arc<Config>,
        _app_config: Arc<AppConfig>,
    ) -> Result<Box<dyn TUN>> {
        info!("Creating macOS TUN device '{}'", name);
        let tun = Tun::builder()
            .name(name)
            .tap(false)
            .packet_info(false)
            .up()
            .try_build()?;
        
        let actual_name = tun.name();
        info!("TUN device created with actual name: {}", actual_name);

        let mtu = config.interface.mtu;
        run_cmd(&format!("ifconfig {} mtu {}", actual_name, mtu))?;

        for addr_str in &config.interface.addresses {
            let network = IpNetwork::from_str(addr_str)?;
            let ip = network.ip();
            let dest_ip = ip; 
            run_cmd(&format!("ifconfig {} {} {}", actual_name, ip, dest_ip))?;
        }

        for peer in &config.peers {
             for cidr in peer.allowed_ips.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                if let Err(e) = run_cmd(&format!("route add -net {} -interface {}", cidr, actual_name)) {
                    warn!("Failed to add route for {}: {}", cidr, e);
                }
            }
        }
        
        let mut dns_configured_service = None;
        if !config.interface.dns.is_empty() {
            info!("Configuring system DNS for macOS...");
            match configure_macos_dns(&config.interface.dns) {
                Ok(service_name) => {
                    info!("System DNS configured on service '{}' to use: {}", &service_name, &config.interface.dns);
                    dns_configured_service = Some(service_name);
                }
                Err(e) => {
                    warn!("Failed to configure system DNS: {}. DNS queries may leak.", e);
                }
            }
        }

        if !config.interface.post_up.is_empty() {
            let cmd = config.interface.post_up.replace("%i", actual_name);
            info!("Running PostUp command: {}", &cmd);
            if let Err(e) = run_cmd(&cmd) {
                warn!("PostUp command failed: {}", e);
            }
        }

        info!("TUN device '{}' is up and configured.", actual_name);

        Ok(Box::new(Self {
            iface: Arc::new(Mutex::new(tun)),
            name: actual_name.to_string(),
            config,
            dns_configured_service,
        }))
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut fixed_buf = Vec::with_capacity(buf.len() + 4);
        if buf.get(0).map_or(false, |&b| (b >> 4) == 4) {
            fixed_buf.extend_from_slice(&[0, 0, 0, 2]); // AF_INET
        } else if buf.get(0).map_or(false, |&b| (b >> 4) == 6) {
            fixed_buf.extend_from_slice(&[0, 0, 0, 30]); // AF_INET6
        } else {
            fixed_buf.extend_from_slice(&[0, 0, 0, 2]);
        }
        fixed_buf.extend_from_slice(buf);
        self.iface.lock().await.write(&fixed_buf).await.map_err(Into::into)
    }

    async fn read(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; (self.config.interface.mtu + 512) as usize];
        let n = self.iface.lock().await.read(&mut buf).await?;
        if n > 4 {
            Ok(buf[4..n].to_vec())
        } else {
            Ok(Vec::new())
        }
    }
    
     async fn try_clone(&self) -> Result<Box<dyn TUN>> {
        Ok(Box::new(TUNDevice {
            iface: self.iface.clone(),
            name: self.name.clone(),
            config: self.config.clone(),
            dns_configured_service: self.dns_configured_service.clone(),
        }))
    }
}

impl Drop for TUNDevice {
    fn drop(&mut self) {
        info!("Cleaning up TUN device '{}'", self.name);

        if let Some(service) = &self.dns_configured_service {
            if let Err(e) = restore_macos_dns(service) {
                warn!("Failed to restore original DNS settings for service '{}': {}", service, e);
            } else {
                info!("Original DNS settings restored for service '{}'.", service);
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

fn get_primary_network_service() -> Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("networksetup -listallnetworkservices | tail -n +2")
        .output()?;
    let services = String::from_utf8_lossy(&output.stdout);
    for service in services.lines() {
        if service.to_lowercase().contains("wan") || service.to_lowercase().contains("wi-fi") || service.to_lowercase().contains("ethernet") {
             if let Ok(output) = Command::new("networksetup").arg("-getinfo").arg(service).output() {
                let info_str = String::from_utf8_lossy(&output.stdout);
                if info_str.contains("IP address:") && !info_str.contains("IP address: none") {
                    return Ok(service.to_string());
                }
            }
        }
    }
    Err(anyhow!("Could not determine primary network service"))
}

fn configure_macos_dns(dns_servers: &str) -> Result<String> {
    let service = get_primary_network_service()?;
    let servers_str = dns_servers.replace(',', " ");
    let cmd = format!("networksetup -setdnsservers \"{}\" {}", service, servers_str);
    run_cmd(&cmd)?;
    Ok(service)
}

fn restore_macos_dns(service_name: &str) -> Result<()> {
    let cmd = format!("networksetup -setdnsservers \"{}\" empty", service_name);
    run_cmd(&cmd)
}

fn run_cmd(cmd: &str) -> Result<()> {
    let args: Vec<&str> = cmd.split_whitespace().collect();
    if args.is_empty() { return Ok(()); }
    let output = Command::new(args[0]).args(&args[1..]).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Command '{}' failed: {}", cmd, stderr));
    }
    Ok(())
}