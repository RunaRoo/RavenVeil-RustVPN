use anyhow::{anyhow, Context, Result};
use x25519_dalek::StaticSecret;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use crate::config::Config;
use crate::app_config::AppConfig;
use std::sync::Arc;
use std::path::Path;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Loads the local X25519 private key from the config.
pub fn load_our_static_key(config: &Arc<Config>) -> Result<StaticSecret> {
    let bytes = B64.decode(&config.interface.private_key)
        .map_err(|e| anyhow!("Invalid private key base64: {}", e))?;
    let arr: [u8; 32] = bytes.as_slice().try_into()
        .map_err(|_| anyhow!("Private key must be 32 bytes"))?;
    Ok(StaticSecret::from(arr))
}

/// Loads TLS certificates and keys to create a Quinn Server Config.
pub fn load_server_config(config: &Arc<Config>, app_config: &Arc<AppConfig>) -> Result<quinn::ServerConfig> {
    let cert_path = Path::new(&app_config.certificate_dir).join(&config.interface.cert_path);
    let key_path = Path::new(&app_config.certificate_dir).join(&config.interface.key_path);
    let ca_path = Path::new(&app_config.certificate_dir).join(&config.interface.ca_cert_path);

    // 1. Load Certificate Chain
    let cert_file = std::fs::read(&cert_path).context("Failed to read CertPath")?;
    let certs = rustls_pemfile::certs(&mut &*cert_file)
        .collect::<Result<Vec<_>, _>>()?;
    let cert_chain: Vec<CertificateDer<'static>> = certs;

    // 2. Load Private Key
    let key_file = std::fs::read(&key_path).context("Failed to read KeyPath")?;
    let keys = rustls_pemfile::pkcs8_private_keys(&mut &*key_file)
        .collect::<Result<Vec<_>, _>>()?;
    let key_der = keys.into_iter().next()
        .ok_or_else(|| anyhow!("No PKCS8 private key found in {:?}", key_path))?;

    // 3. Load CA for Client Auth (mTLS)
    let ca_file = std::fs::read(&ca_path).context("Failed to read CaCertPath")?;
    let ca_certs = rustls_pemfile::certs(&mut &*ca_file)
        .collect::<Result<Vec<_>, _>>()?;

    let mut client_auth_roots = rustls::RootCertStore::empty();
    for root in ca_certs {
        client_auth_roots.add(root)?;
    }

    // 4. Build Rustls Config
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(client_auth_roots.into())
        .build()?;

    let server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, PrivateKeyDer::Pkcs8(key_der))?;

    // Fix: Use QuicServerConfig::try_from to satisfy the trait bound
    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    // Configure Transport parameters
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

/// Loads TLS certificates to create a Quinn Client Config.
pub fn load_client_config(config: &Arc<Config>, app_config: &Arc<AppConfig>) -> Result<quinn::ClientConfig> {
    let cert_path = Path::new(&app_config.certificate_dir).join(&config.interface.cert_path);
    let key_path = Path::new(&app_config.certificate_dir).join(&config.interface.key_path);
    let ca_path = Path::new(&app_config.certificate_dir).join(&config.interface.ca_cert_path);

    // 1. Load Certificate Chain
    let cert_file = std::fs::read(&cert_path).context("Failed to read CertPath")?;
    let certs = rustls_pemfile::certs(&mut &*cert_file)
        .collect::<Result<Vec<_>, _>>()?;
    let cert_chain: Vec<CertificateDer<'static>> = certs;

    // 2. Load Private Key
    let key_file = std::fs::read(&key_path).context("Failed to read KeyPath")?;
    let keys = rustls_pemfile::pkcs8_private_keys(&mut &*key_file)
        .collect::<Result<Vec<_>, _>>()?;
    let key_der = keys.into_iter().next()
        .ok_or_else(|| anyhow!("No PKCS8 private key found in {:?}", key_path))?;

    // 3. Load CA to verify Server
    let ca_file = std::fs::read(&ca_path).context("Failed to read CaCertPath")?;
    let ca_certs = rustls_pemfile::certs(&mut &*ca_file)
        .collect::<Result<Vec<_>, _>>()?;

    let mut root_store = rustls::RootCertStore::empty();
    for root in ca_certs {
        root_store.add(root)?;
    }

    // 4. Build Rustls Config
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, PrivateKeyDer::Pkcs8(key_der))?;

    // Fix: Use QuicClientConfig::try_from
    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}