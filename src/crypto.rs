use rand_core::RngCore;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use std::time::Instant;
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
pub const REPLAY_WINDOW_SIZE: u64 = 64;

// --- Keypair ---
#[derive(Clone, Debug)]
pub struct Keypair {
    pub send_key: [u8; KEY_SIZE],
    pub recv_key: [u8; KEY_SIZE],
    pub birthdate: Instant,
    pub send_nonce: u64,
    pub last_recv_nonce: u64,
    pub recv_nonce_bitmap: u64,
}

impl Keypair {
    pub fn new(send_key: [u8; KEY_SIZE], recv_key: [u8; KEY_SIZE]) -> Self {
        Keypair {
            send_key,
            recv_key,
            birthdate: Instant::now(),
            send_nonce: 0,
            last_recv_nonce: 0,
            recv_nonce_bitmap: 0,
        }
    }
}

// --- NoiseState (Fixed: Added Debug) ---
#[derive(Default, Debug)]
pub struct NoiseState {
    pub current_keypair: Option<Keypair>,
    pub previous_keypair: Option<Keypair>,
    pub next_keypair: Option<Keypair>,
}

impl NoiseState {
    pub fn new() -> Self {
        Default::default()
    }
}

// --- Helper Functions ---

pub fn generate_keys_cli() -> Result<(String, String)> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let priv_key_b64 = B64.encode(secret.to_bytes());
    let pub_key_b64 = B64.encode(public.as_bytes());
    Ok((priv_key_b64, pub_key_b64))
}

pub fn generate_preshared_key() -> Result<String> {
    let mut key = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    Ok(B64.encode(key))
}

pub fn decode_psk(psk_b64: &str) -> Result<[u8; KEY_SIZE]> {
    if psk_b64.is_empty() {
        return Ok([0u8; KEY_SIZE]);
    }
    let psk_bytes = B64.decode(psk_b64)
        .map_err(|e| anyhow!("Preshared key is not valid base64: {}", e))?;
    psk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("Preshared key must be exactly {} bytes", KEY_SIZE))
}

pub fn derive_keys(
    our_static_privkey: &StaticSecret,
    our_eph_privkey: &ReusableSecret,
    their_static_pubkey: &PublicKey,
    their_eph_pubkey: &PublicKey,
    psk: &[u8; KEY_SIZE],
    is_initiator: bool,
    _kyber_shared_secret: Option<&[u8]>,
) -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE])> {
    let mut prk = Hkdf::<Sha256>::extract(Some(b"RavenVeil-Initial-Salt"), psk).0;
    let dh_ss = our_static_privkey.diffie_hellman(their_static_pubkey);
    let dh_se = our_static_privkey.diffie_hellman(their_eph_pubkey);
    let dh_es = our_eph_privkey.diffie_hellman(their_static_pubkey);
    let dh_ee = our_eph_privkey.diffie_hellman(their_eph_pubkey);

    if is_initiator {
        prk = Hkdf::<Sha256>::extract(Some(&prk), dh_se.as_bytes()).0;
        prk = Hkdf::<Sha256>::extract(Some(&prk), dh_es.as_bytes()).0;
    } else {
        prk = Hkdf::<Sha256>::extract(Some(&prk), dh_es.as_bytes()).0;
        prk = Hkdf::<Sha256>::extract(Some(&prk), dh_se.as_bytes()).0;
    }

    prk = Hkdf::<Sha256>::extract(Some(&prk), dh_ss.as_bytes()).0;
    prk = Hkdf::<Sha256>::extract(Some(&prk), dh_ee.as_bytes()).0;

    let hkdf_expander = Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|e| anyhow!("Failed to create HKDF expander from PRK: {}", e))?;

    let mut okm = [0u8; KEY_SIZE * 2];
    hkdf_expander.expand(b"session-keys", &mut okm)
        .map_err(|e| anyhow!("HKDF expand failed: {}", e))?;

    let send_key: [u8; KEY_SIZE] = okm[..KEY_SIZE].try_into()?;
    let recv_key: [u8; KEY_SIZE] = okm[KEY_SIZE..].try_into()?;

    if is_initiator {
        Ok((send_key, recv_key))
    } else {
        Ok((recv_key, send_key))
    }
}

pub fn encrypt_packet(
    key: &[u8; KEY_SIZE],
    nonce_val: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes[..8].copy_from_slice(&nonce_val.to_le_bytes());
    let nonce: XNonce = nonce_bytes.into();

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    let mut result = Vec::with_capacity(8 + ciphertext.len());
    result.extend_from_slice(&nonce_val.to_le_bytes());
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt_packet(keypair: &mut Keypair, packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < (8 + TAG_SIZE) {
        return Err(anyhow!("Packet too short for decryption"));
    }
    let nonce_val = u64::from_le_bytes(packet[..8].try_into()?);
    let ciphertext = &packet[8..];

    if nonce_val > keypair.last_recv_nonce {
        let shift = nonce_val.saturating_sub(keypair.last_recv_nonce);
        if shift >= REPLAY_WINDOW_SIZE {
            keypair.recv_nonce_bitmap = 1;
        } else {
            keypair.recv_nonce_bitmap = (keypair.recv_nonce_bitmap << shift) | 1;
        }
        keypair.last_recv_nonce = nonce_val;
    } else {
        let diff = keypair.last_recv_nonce - nonce_val;
        if diff >= REPLAY_WINDOW_SIZE {
            return Err(anyhow!("Replay detected: nonce too old"));
        }
        if (keypair.recv_nonce_bitmap >> diff) & 1 == 1 {
            return Err(anyhow!("Replay detected: nonce already seen"));
        }
        keypair.recv_nonce_bitmap |= 1 << diff;
    }

    let cipher = XChaCha20Poly1305::new((&keypair.recv_key).into());
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes[..8].copy_from_slice(&nonce_val.to_le_bytes());
    let nonce: XNonce = nonce_bytes.into();

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {}", e))
}

pub fn try_decrypt_with_rotation(noise: &mut NoiseState, packet: &[u8]) -> Result<Vec<u8>> {
    if let Some(kp) = &mut noise.current_keypair {
        if let Ok(plaintext) = decrypt_packet(kp, packet) {
            return Ok(plaintext);
        }
    }

    if let Some(kp) = &mut noise.previous_keypair {
        if let Ok(plaintext) = decrypt_packet(kp, packet) {
            noise.previous_keypair = None;
            return Ok(plaintext);
        }
    }

    Err(anyhow!("Decryption failed with all available keys"))
}