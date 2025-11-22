/*
DoH feature disable for now
Standard dns requests handled by os,
so we don't need this external resolver.

Keep for future DoH/DoS implementations
 */



/*
use anyhow::{anyhow, Result};
use log::info;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use trust_dns_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::TokioAsyncResolver;
use crate::config::InterfaceConfig;

pub struct DnsResolver {
    resolver: TokioAsyncResolver,
}

impl DnsResolver {
    /// Creates a new DNS resolver based on the provided interface configuration.
    pub async fn new(config: &InterfaceConfig) -> Result<Self> {
        if !config.doh.is_empty() {
            info!("DNS-over-HTTPS (DoH) is configured but the feature is disabled in this build. Falling back to standard DNS.");
        }
        info!("Using standard DNS servers: {}", &config.dns);
        Self::create_standard_resolver(&config.dns)
    }

    /// Creates a standard UDP/TCP DNS resolver from the servers listed in the config.
    fn create_standard_resolver(dns_servers: &str) -> Result<Self> {
        let resolver_config = if dns_servers.is_empty() {
            info!("No DNS servers specified, using default (1.1.1.1).");
            let mut config = ResolverConfig::new();
            let cloudflare_dns: IpAddr = "1.1.1.1".parse()?;
            config.add_name_server(NameServerConfig::new(SocketAddr::new(cloudflare_dns, 53), Protocol::Udp));
            config
        } else {
            let mut config = ResolverConfig::new();
            for server in dns_servers.split(',') {
                let addr_str = server.trim();
                if addr_str.is_empty() { continue; }

                let addr: IpAddr = addr_str.parse()
                    .map_err(|e| anyhow!("Invalid DNS server address '{}': {}", addr_str, e))?;
                config.add_name_server(NameServerConfig::new(SocketAddr::new(addr, 53), Protocol::Udp));
            }
            config
        };

        let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());
        Ok(Self { resolver })
    }

    /// Resolves a hostname to an IP address.
    pub async fn resolve(&self, host: &str) -> Result<IpAddr, ResolveError> {
        if let Ok(ip) = IpAddr::from_str(host) {
            return Ok(ip);
        }
        let response = self.resolver.lookup_ip(host).await?;
        response.iter().next().ok_or_else(|| {
            ResolveError::from(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No IP address found for host: {}", host),
            ))
        })
    }
}

 */