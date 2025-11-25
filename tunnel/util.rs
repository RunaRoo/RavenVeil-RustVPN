use anyhow::{anyhow, Context, Result};
use crate::config::Config;
use crate::app_config::AppConfig;
use std::sync::Arc;
use std::path::Path;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use log::info;

fn configure_transport() -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();

    // 1. Enable Datagrams (Essential for VPN)
    transport.datagram_receive_buffer_size(Some(1024 * 1024 * 20));
    transport.datagram_send_buffer_size(1024 * 1024 * 20);

    // 2. Enable GSO (Generic Segmentation Offload)
    transport.enable_segmentation_offload(true);

    // 3. Keepalive
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));

    // 4. Aggressive Congestion Control (BBR)
    // FIX: Correct way to set BBR in Quinn 0.11
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    Ok(transport)
}

fn load_certs(app_config: &Arc<AppConfig>, cert: &str, key: &str, ca: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, Vec<CertificateDer<'static>>)> {
    let cert_path = Path::new(&app_config.certificate_dir).join(cert);
    let key_path = Path::new(&app_config.certificate_dir).join(key);
    let ca_path = Path::new(&app_config.certificate_dir).join(ca);

    let cert_file = std::fs::read(&cert_path).context("Failed to read CertPath")?;
    let certs = rustls_pemfile::certs(&mut &*cert_file).collect::<Result<Vec<_>, _>>()?;

    let key_file = std::fs::read(&key_path).context("Failed to read KeyPath")?;
    let keys = rustls_pemfile::pkcs8_private_keys(&mut &*key_file).collect::<Result<Vec<_>, _>>()?;
    let key = keys.into_iter().next().ok_or_else(|| anyhow!("No PKCS8 key found"))?;

    let ca_file = std::fs::read(&ca_path).context("Failed to read CaCertPath")?;
    let ca_certs = rustls_pemfile::certs(&mut &*ca_file).collect::<Result<Vec<_>, _>>()?;

    Ok((certs, PrivateKeyDer::Pkcs8(key), ca_certs))
}

pub fn load_server_config(config: &Arc<Config>, app_config: &Arc<AppConfig>) -> Result<quinn::ServerConfig> {
    let (cert_chain, key, ca_certs) = load_certs(app_config, &config.interface.cert_path, &config.interface.key_path, &config.interface.ca_cert_path)?;

    let mut client_auth_roots = rustls::RootCertStore::empty();
    for root in ca_certs {
        client_auth_roots.add(root)?;
    }

    let client_verifier = rustls::server::WebPkiClientVerifier::builder(client_auth_roots.into()).build()?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let server_crypto = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?
    ));

    server_config.transport_config(Arc::new(configure_transport()?));

    if config.interface.post_quantum {
        info!("Post-Quantum Hybrid Key Exchange enabled (AWS-LC).");
    }

    Ok(server_config)
}

pub fn load_client_config(config: &Arc<Config>, app_config: &Arc<AppConfig>) -> Result<quinn::ClientConfig> {
    let (cert_chain, key, ca_certs) = load_certs(app_config, &config.interface.cert_path, &config.interface.key_path, &config.interface.ca_cert_path)?;

    let mut root_store = rustls::RootCertStore::empty();
    for root in ca_certs {
        root_store.add(root)?;
    }

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let client_crypto = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, key)?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?
    ));

    client_config.transport_config(Arc::new(configure_transport()?));

    Ok(client_config)
}