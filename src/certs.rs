use anyhow::Result;
use rcgen::{Certificate, CertificateParams, DistinguishedName, KeyPair, SanType};
use std::fs;
use std::time::Duration;
use time::OffsetDateTime;

pub fn generate_ca(cert_path: &str, key_path: &str) -> Result<()> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::OrganizationName, "RavenVeil VPN");
    dn.push(rcgen::DnType::CommonName, "RavenVeil VPN CA");
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::from_secs(365 * 24 * 3600 * 10);

    let cert = Certificate::from_params(params)?;
    fs::write(cert_path, cert.serialize_pem()?)?;
    fs::write(key_path, cert.serialize_private_key_pem())?;
    Ok(())
}

pub fn generate_peer_cert(
    _ca_cert_path: &str, // Not needed for this method, but kept for API consistency
    ca_key_path: &str,
    peer_cert_path: &str,
    peer_key_path: &str,
    peer_names: &str,
) -> Result<()> {
    // Load the CA's private key
    let ca_key_pem = fs::read_to_string(ca_key_path)?;
    let ca_key_pair = KeyPair::from_pem(&ca_key_pem)?;

    // Re-create the CA certificate object from scratch to use it for signing.
    // This avoids parsing issues with the rcgen library.
    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(rcgen::DnType::OrganizationName, "RavenVeil VPN");
    ca_dn.push(rcgen::DnType::CommonName, "RavenVeil VPN CA");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    ca_params.not_before = OffsetDateTime::now_utc() - Duration::from_secs(60); // Ensure it's valid now
    ca_params.not_after = OffsetDateTime::now_utc() + Duration::from_secs(365 * 24 * 3600 * 10);
    
    // Attach the loaded private key to the recreated CA parameters
    ca_params.key_pair = Some(ca_key_pair); 
    
    // Create the final CA certificate object, ready for signing
    let ca_cert = Certificate::from_params(ca_params)?;

    // Now, create the parameters for the new peer certificate
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::OrganizationName, "RavenVeil VPN Peer");
    params.distinguished_name = dn;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyEncipherment,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    
    // Add multiple Subject Alternative Names (IPs or DNS names)
    let subject_alt_names: Vec<SanType> = peer_names
        .split(',')
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
        .map(|name| {
            if let Ok(ip) = name.parse::<std::net::IpAddr>() {
                SanType::IpAddress(ip)
            } else {
                SanType::DnsName(name.to_string())
            }
        })
        .collect();

    if subject_alt_names.is_empty() {
        return Err(anyhow::anyhow!("At least one IP address or DNS name must be provided for the peer certificate."));
    }
    params.subject_alt_names = subject_alt_names;

    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::from_secs(365 * 24 * 3600);

    // Generate the peer certificate
    let cert = Certificate::from_params(params)?;
    
    // Sign it with the CA
    let signed_pem = cert.serialize_pem_with_signer(&ca_cert)?;

    // Write the new peer certificate and its private key to files
    fs::write(peer_cert_path, signed_pem)?;
    fs::write(peer_key_path, cert.serialize_private_key_pem())?;
    Ok(())
}
