//! socks.rs - SOCKS5 proxy logic for RavenVeil.
//!
//! This module implements both the "client" and "server" sides of a SOCKS5 proxy
//! that tunnels its traffic over the RavenVeil QUIC transport.
//!
//! It works by multiplexing multiple SOCKS connections over the single tunnel
//! stream using a simple 4-byte connection ID prefix.
//!
//! --- SOCKS Client Mode (`run_socks_client_mode`) ---
//! 1.  Listens on a local port (e.g., 127.0.0.1:1080).
//! 2.  Spawns `client_receiver_loop` to listen for all incoming data from the tunnel.
//! 3.  When a browser connects, it spawns `handle_socks_client_connection`.
//! 4.  `handle_socks_client_connection`:
//!     a.  Assigns a unique `conn_id`.
//!     b.  Stores a channel in a shared map for the receiver loop to send data back.
//!     c.  Performs the SOCKS5 handshake with the browser.
//!     d.  Receives the destination address (e.g., "google.com:80").
//!     e.  Sends the SOCKS5 request packet, *prefixed with the `conn_id`*, to the tunnel.
//!     f.  Waits for the SOCKS5 reply from the server (via its channel).
//!     g.  Sends the reply to the browser.
//!     h.  Enters a loop, copying data between the browser and the tunnel (prefixing
//!         outgoing data and receiving from its channel).
//!
//! --- SOCKS Server Mode (`run_socks_server_mode`) ---
//! 1.  Spawns `server_receiver_loop` to listen for all incoming data from the tunnel.
//! 2.  `server_receiver_loop`:
//!     a.  Receives a packet from the tunnel.
//!     b.  Parses the `conn_id` prefix.
//!     c.  Checks a shared map if this `conn_id` is already known.
//!     d.  If known, it forwards the data to the correct handler task.
//!     e.  If *unknown*, this is a new connection. It spawns
//!         `handle_socks_server_connection`, creates a channel, and stores it in the map.
//! 3.  `handle_socks_server_connection`:
//!     a.  The first packet it receives *is* the SOCKS5 request from the client.
//!     b.  It parses this request to get the real destination (e.g., "google.com:80").
//!     c.  It connects to the real destination using `TcpStream::connect`.
//!     d.  It sends a SOCKS5 success reply *back* to the client (prefixed with `conn_id`).
//!     e.  It enters a loop, copying data between the real destination and the
//!         tunnel (prefixing outgoing data and receiving from its channel).

//
//! socks.rs - SOCKS5 proxy logic for RavenVeil.
use crate::app_config::AppConfig;
use crate::config::PeerConfig;
use crate::tunnel::{TunnelCommand, TunnelEvent};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};

// --- Shared Types ---

/// A map from Connection ID -> Channel to send data to the handler task.
type ConnectionMap = Arc<RwLock<HashMap<u32, mpsc::Sender<Bytes>>>>;

/// We need to find the "exit" peer (the one acting as SOCKS server).
/// We'll define it as the first peer that allows "0.0.0.0/0".
fn find_exit_peer_key(
    peer_configs: &[PeerConfig],
) -> Result<[u8; 32]> {
    let peer = peer_configs
        .iter()
        .find(|p| p.allowed_ips.contains("0.0.0.0/0"))
        .ok_or_else(|| anyhow!("No peer found with AllowedIPs '0.0.0.0/0'. Cannot determine SOCKS exit node."))?;

    let key_bytes = B64
        .decode(&peer.public_key)
        .context("Failed to decode peer public key")?;

    key_bytes.as_slice().try_into()
        .map_err(|_| anyhow!("Peer public key is not 32 bytes"))
}

// --- SOCKS Client Mode ---

/// Runs the SOCKS5 client listener.
pub async fn run_socks_client_mode(
    app_config: Arc<AppConfig>,
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    from_tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelEvent>>>,
    vpn_config: Arc<crate::config::Config>,
) -> Result<()> {
    // This map stores a channel for each active connection. The receiver loop
    // uses it to send data back to the correct connection handler.
    let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));

    // Find the peer we'll be sending all our SOCKS traffic to.
    let exit_peer_key = find_exit_peer_key(&vpn_config.peers)?;
    info!("SOCKS5 exit peer found: {}", B64.encode(exit_peer_key));

    // Spawn a single task to receive all data from the tunnel
    tokio::spawn(client_receiver_loop(
        from_tunnel_rx,
        connections.clone(),
    ));

    // Start listening for local SOCKS connections (e.g., from a browser)
    let listen_addr = &app_config.socks5.socks_listen_address;
    info!("Starting SOCKS5 client listener on {}", listen_addr);
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("Failed to bind SOCKS5 listener to {}", listen_addr))?;

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                debug!("Accepted SOCKS connection from {}", peer_addr);
                tokio::spawn(handle_socks_client_connection(
                    stream,
                    exit_peer_key,
                    to_tunnel_tx.clone(),
                    connections.clone(),
                ));
            }
            Err(e) => {
                error!("Failed to accept SOCKS connection: {}", e);
            }
        }
    }
}

/// A single task that handles one SOCKS5 connection from a local application.
async fn handle_socks_client_connection(
    mut stream: TcpStream,
    exit_peer_key: [u8; 32],
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    connections: ConnectionMap,
) -> Result<()> {
    // Generate a unique ID for this connection
    static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(1);
    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);

    // Create a channel for the receiver loop to send data back to us
    let (tx, mut rx) = mpsc::channel(128);
    connections.write().await.insert(conn_id, tx);

    debug!("Conn {}: Handling new SOCKS connection", conn_id);

    // 1. Perform SOCKS5 Handshake
    let socks_request = match perform_socks_handshake(&mut stream).await {
        Ok(req) => req,
        Err(e) => {
            error!("Conn {}: SOCKS handshake failed: {}", conn_id, e);
            connections.write().await.remove(&conn_id);
            return Err(e);
        }
    };

    // 2. Send the SOCKS5 request (e.g., "connect to google.com:80") to the server
    //    We prefix it with our connection ID.
    let mut payload = BytesMut::with_capacity(4 + socks_request.len());
    payload.put_u32_le(conn_id);
    payload.put(socks_request);

    let cmd = TunnelCommand::SendData {
        destination_key: exit_peer_key,
        payload: payload.freeze(),
    };
    if let Err(e) = to_tunnel_tx.send(cmd).await {
        error!("Conn {}: Failed to send SOCKS request to tunnel: {}", conn_id, e);
        connections.write().await.remove(&conn_id);
        return Err(e.into());
    }

    // 3. Wait for the SOCKS5 reply from the server
    debug!("Conn {}: Waiting for SOCKS reply from server...", conn_id);
    let server_reply = match rx.recv().await {
        Some(reply) => reply,
        None => {
            error!("Conn {}: Channel closed while waiting for SOCKS reply", conn_id);
            connections.write().await.remove(&conn_id);
            return Err(anyhow!("Connection closed by receiver"));
        }
    };

    // 4. Send the reply back to the browser
    if let Err(e) = stream.write_all(&server_reply).await {
        error!("Conn {}: Failed to send SOCKS reply to browser: {}", conn_id, e);
        connections.write().await.remove(&conn_id);
        return Err(e.into());
    }

    debug!("Conn {}: SOCKS connection established. Pumping data.", conn_id);

    // 5. Pump data in both directions
    let (mut stream_read, mut stream_write) = stream.split();
    let mut read_buf = BytesMut::with_capacity(2048);

    loop {
        tokio::select! {
            // Data from browser -> tunnel
            result = stream_read.read_buf(&mut read_buf) => {
                match result {
                    Ok(0) | Err(_) => {
                        debug!("Conn {}: Browser closed connection.", conn_id);
                        break; // Connection closed
                    }
                    Ok(n) => {
                        let mut payload = BytesMut::with_capacity(4 + n);
                        payload.put_u32_le(conn_id);
                        payload.put_slice(&read_buf[..n]);
                        read_buf.advance(n);

                        let cmd = TunnelCommand::SendData {
                            destination_key: exit_peer_key,
                            payload: payload.freeze(),
                        };
                        if to_tunnel_tx.send(cmd).await.is_err() {
                            debug!("Conn {}: Tunnel closed. Exiting.", conn_id);
                            break;
                        }
                    }
                }
            },

            // Data from tunnel -> browser
            Some(data) = rx.recv() => {
                if let Err(e) = stream_write.write_all(&data).await {
                    debug!("Conn {}: Failed to write to browser: {}. Exiting.", conn_id, e);
                    break;
                }
            },

            else => {
                break;
            }
        }
    }

    // Cleanup
    debug!("Conn {}: Closing connection.", conn_id);
    connections.write().await.remove(&conn_id);
    Ok(())
}

/// The single receiver loop for *all* client connections.
/// It reads from the tunnel and dispatches data to the correct handler.
async fn client_receiver_loop(
    from_tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelEvent>>>,
    connections: ConnectionMap,
) {
    info!("SOCKS client receiver loop started.");
    let mut rx_guard = from_tunnel_rx.lock().await;

    loop {
        match rx_guard.recv().await {
            Some(TunnelEvent::DataReceived { mut payload, .. }) => {
                if payload.len() < 4 {
                    warn!("Received data packet too short to contain conn_id. Discarding.");
                    continue;
                }

                let conn_id = payload.get_u32_le();
                let data = payload.slice(4..); // Get remaining data

                if let Some(tx) = connections.read().await.get(&conn_id) {
                    if tx.send(data).await.is_err() {
                        debug!("Conn {}: Handler task is gone. Removing.", conn_id);
                        // The handler task will remove itself, but we can do it too
                        connections.write().await.remove(&conn_id);
                    }
                } else {
                    warn!("Received data for unknown conn_id {}. Discarding.", conn_id);
                }
            }
            None => {
                info!("SOCKS client receiver: Tunnel channel closed. Exiting.");
                break;
            }
        }
    }
}

/// Performs the SOCKS5 handshake with the client stream (browser).
/// Returns the SOCKS5 request packet (e.g., "connect to google.com:80").
async fn perform_socks_handshake(stream: &mut TcpStream) -> Result<Bytes> {
    // 1. Read method selection
    let mut buf = [0u8; 257];
    let n = stream.read(&mut buf).await.context("Failed to read SOCKS handshake")?;
    if n < 3 || buf[0] != 0x05 {
        return Err(anyhow!("Invalid SOCKS5 handshake: version not 5"));
    }

    // We only support "No Authentication" (0x00)
    let nmethods = buf[1] as usize;
    if n < (2 + nmethods) {
        return Err(anyhow!("Invalid SOCKS5 handshake: method length mismatch"));
    }
    let methods = &buf[2..2 + nmethods];
    if !methods.contains(&0x00) {
        // Send "No acceptable methods"
        stream.write_all(&[0x05, 0xFF]).await?;
        return Err(anyhow!("SOCKS5 client does not support 'No Authentication'"));
    }

    // 2. Send "No Authentication"
    stream.write_all(&[0x05, 0x00]).await.context("Failed to send SOCKS method reply")?;

    // 3. Read the SOCKS request
    let n = stream.read(&mut buf).await.context("Failed to read SOCKS request")?;
    if n < 5 {
        return Err(anyhow!("Invalid SOCKS request: too short"));
    }
    if buf[0] != 0x05 || buf[1] != 0x01 /* CMD_CONNECT */ {
        // Send "Command not supported"
        let reply = [0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        stream.write_all(&reply).await?;
        return Err(anyhow!("SOCKS command not supported (we only support CONNECT)"));
    }

    // buf[3] is ATYP (Address Type)
    let req_len = match buf[3] {
        0x01 => 4 + 4 + 2, // IPv4: 4 + 4 + 2
        0x03 => 4 + 1 + buf[4] as usize + 2, // Domain: 4 + 1 + len + 2
        0x04 => 4 + 16 + 2, // IPv6: 4 + 16 + 2
        _ => {
            let reply = [0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // Address type not supported
            stream.write_all(&reply).await?;
            return Err(anyhow!("SOCKS address type not supported"));
        }
    };
    if n < req_len {
        return Err(anyhow!("Invalid SOCKS request: length mismatch for address type"));
    }

    // Return the full request packet
    Ok(Bytes::copy_from_slice(&buf[..req_len]))
}

// --- SOCKS Server Mode ---

/// Runs the SOCKS5 server. It just waits for the receiver loop to do all the work.
pub async fn run_socks_server_mode(
    _app_config: Arc<AppConfig>, // Renamed to mark as unused
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    from_tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelEvent>>>,
) -> Result<()> {
    // This map stores a channel for each active connection. The receiver loop
    // uses it to send data to the correct connection handler.
    let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
    info!("SOCKS5 server mode started. Waiting for client connections via tunnel.");

    // Spawn a single task to receive all data from the tunnel
    tokio::spawn(server_receiver_loop(
        from_tunnel_rx,
        connections,
        to_tunnel_tx,
    ));

    // Server just waits for shutdown
    tokio::signal::ctrl_c().await?;
    info!("SOCKS5 server shutting down.");
    Ok(())
}

/// The single receiver loop for the *server*.
/// It reads from the tunnel and dispatches data to existing handlers,
/// or creates new handlers for new connections.
async fn server_receiver_loop(
    from_tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelEvent>>>,
    connections: ConnectionMap,
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
) {
    info!("SOCKS server receiver loop started.");
    let mut rx_guard = from_tunnel_rx.lock().await;

    loop {
        match rx_guard.recv().await {
            Some(TunnelEvent::DataReceived { mut payload, source_key }) => { // Make payload mutable
                if payload.len() < 4 {
                    warn!("Received data packet too short to contain conn_id. Discarding.");
                    continue;
                }

                let conn_id = payload.get_u32_le();
                let data = payload.slice(4..); // Get remaining data

                let connections_guard = connections.read().await;
                if let Some(tx) = connections_guard.get(&conn_id) {
                    // Existing connection
                    if tx.send(data).await.is_err() {
                        debug!("Conn {}: Handler task is gone. Removing.", conn_id);
                        drop(connections_guard); // Release read lock
                        connections.write().await.remove(&conn_id);
                    }
                } else {
                    // New connection
                    drop(connections_guard); // Release read lock
                    debug!("Conn {}: New SOCKS connection from peer {}", conn_id, B64.encode(source_key));

                    let (tx, rx) = mpsc::channel(128);
                    connections.write().await.insert(conn_id, tx);

                    tokio::spawn(handle_socks_server_connection(
                        conn_id,
                        source_key,
                        data, // This first packet *is* the SOCKS request
                        rx,
                        to_tunnel_tx.clone(),
                        connections.clone(),
                    ));
                }
            }
            None => {
                info!("SOCKS server receiver: Tunnel channel closed. Exiting.");
                break;
            }
        }
    }
}

/// A single task that handles one proxied SOCKS5 connection on the server.
async fn handle_socks_server_connection(
    conn_id: u32,
    source_peer_key: [u8; 32],
    first_payload: Bytes, // This is the SOCKS request from the client
    mut rx: mpsc::Receiver<Bytes>, // Receives data from the tunnel
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    connections: ConnectionMap,
) -> Result<()> {
    debug!("Conn {}: Handling new server-side connection", conn_id);

    // 1. Parse the SOCKS request from the first payload
    let dest_addr = match parse_socks_request(&first_payload) {
        Ok(addr) => addr,
        Err(e) => {
            error!("Conn {}: Failed to parse SOCKS request: {}", conn_id, e);
            // TODO: Send SOCKS error reply
            connections.write().await.remove(&conn_id);
            return Err(e);
        }
    };

    // 2. Connect to the real destination
    debug!("Conn {}: Connecting to {}", conn_id, dest_addr);
    let dest_stream = match TcpStream::connect(&dest_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Conn {}: Failed to connect to {}: {}", conn_id, dest_addr, e);
            // Send SOCKS "Host Unreachable" reply
            let reply = [0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            let mut payload = BytesMut::with_capacity(4 + reply.len());
            payload.put_u32_le(conn_id);
            payload.put_slice(&reply);
            let cmd = TunnelCommand::SendData { destination_key: source_peer_key, payload: payload.freeze() };
            let _ = to_tunnel_tx.send(cmd).await;
            connections.write().await.remove(&conn_id);
            return Err(e.into());
        }
    };

    // 3. Send SOCKS success reply back to the client
    debug!("Conn {}: Connected successfully. Sending SOCKS success reply.", conn_id);
    let local_addr = dest_stream.local_addr().unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
    let reply = socks_success_reply(local_addr);
    let mut payload = BytesMut::with_capacity(4 + reply.len());
    payload.put_u32_le(conn_id);
    payload.put(reply.as_slice());

    let cmd = TunnelCommand::SendData {
        destination_key: source_peer_key,
        payload: payload.freeze(),
    };
    if let Err(e) = to_tunnel_tx.send(cmd).await {
        error!("Conn {}: Failed to send SOCKS success reply to tunnel: {}", conn_id, e);
        connections.write().await.remove(&conn_id);
        return Err(e.into());
    }

    // 4. Pump data in both directions
    debug!("Conn {}: Pumping data for connection.", conn_id);
    let (mut dest_read, mut dest_write) = dest_stream.into_split();
    let mut read_buf = BytesMut::with_capacity(2048);

    loop {
        tokio::select! {
            // Data from tunnel -> real destination
            Some(data) = rx.recv() => {
                if let Err(e) = dest_write.write_all(&data).await {
                    debug!("Conn {}: Failed to write to destination {}: {}. Exiting.", conn_id, dest_addr, e);
                    break;
                }
            },

            // Data from real destination -> tunnel
            result = dest_read.read_buf(&mut read_buf) => {
                match result {
                    Ok(0) | Err(_) => {
                        debug!("Conn {}: Destination {} closed connection.", conn_id, dest_addr);
                        break; // Connection closed
                    }
                    Ok(n) => {
                        let mut payload = BytesMut::with_capacity(4 + n);
                        payload.put_u32_le(conn_id);
                        payload.put_slice(&read_buf[..n]);
                        read_buf.advance(n);

                        let cmd = TunnelCommand::SendData {
                            destination_key: source_peer_key,
                            payload: payload.freeze(),
                        };
                        if to_tunnel_tx.send(cmd).await.is_err() {
                            debug!("Conn {}: Tunnel closed. Exiting.", conn_id);
                            break;
                        }
                    }
                }
            },

            else => {
                break;
            }
        }
    }

    // Cleanup
    debug!("Conn {}: Closing connection.", conn_id);
    connections.write().await.remove(&conn_id);
    Ok(())
}

/// Parses a SOCKS5 request packet (from the client) and returns the
/// destination address as a string (e.g., "google.com:80").
fn parse_socks_request(buf: &[u8]) -> Result<String> {
    if buf.len() < 5 || buf[0] != 0x05 || buf[1] != 0x01 {
        return Err(anyhow!("Invalid SOCKS request packet"));
    }

    let atyp = buf[3];
    let (host, port_offset) = match atyp {
        0x01 => { // IPv4
            if buf.len() < 4 + 4 + 2 { return Err(anyhow!("Short IPv4 SOCKS request")); }
            let addr = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            (addr.to_string(), 8)
        }
        0x03 => { // Domain
            let len = buf[4] as usize;
            if buf.len() < 4 + 1 + len + 2 { return Err(anyhow!("Short Domain SOCKS request")); }
            let domain = std::str::from_utf8(&buf[5..5 + len])
                .map_err(|e| anyhow!("Invalid UTF-8 in domain: {}", e))?;
            (domain.to_string(), 5 + len)
        }
        0x04 => { // IPv6
            if buf.len() < 4 + 16 + 2 { return Err(anyhow!("Short IPv6 SOCKS request")); }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let addr = std::net::Ipv6Addr::from(octets);
            (format!("[{}]", addr), 20) // Use brackets for IPv6
        }
        _ => return Err(anyhow!("Unsupported SOCKS address type: {}", atyp)),
    };

    let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
    Ok(format!("{}:{}", host, port))
}

/// Creates a SOCKS5 success reply packet.
fn socks_success_reply(addr: SocketAddr) -> Vec<u8> {
    let mut reply = vec![0x05, 0x00, 0x00]; // VER, REP(Succeeded), RSV
    match addr {
        SocketAddr::V4(v4) => {
            reply.push(0x01); // ATYP(IPv4)
            reply.extend_from_slice(&v4.ip().octets());
            reply.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            reply.push(0x04); // ATYP(IPv6)
            reply.extend_from_slice(&v6.ip().octets());
            reply.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    reply
}