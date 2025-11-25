//! socks.rs - SOCKS5 proxy logic for RavenVeil.
//!
//! Supports:
//! - CMD CONNECT (TCP)
//! - CMD UDP_ASSOCIATE (UDP)
//! - IPv4, IPv6, and Domain Names

use crate::app_config::AppConfig;
use crate::config::PeerConfig;
use crate::tunnel::{TunnelCommand, TunnelEvent};
use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex, RwLock};

type ConnectionMap = Arc<RwLock<HashMap<u32, mpsc::Sender<Bytes>>>>;

fn find_exit_peer_key(
    peer_configs: &[PeerConfig],
) -> Result<String> {
    let peer = peer_configs
        .iter()
        .find(|p| p.allowed_ips.contains("0.0.0.0/0"))
        .ok_or_else(|| anyhow!("No peer found with AllowedIPs '0.0.0.0/0'. Cannot determine SOCKS exit node."))?;

    Ok(peer.public_key.clone())
}

// --- SOCKS Client Mode ---

pub async fn run_socks_client_mode(
    app_config: Arc<AppConfig>,
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    from_tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelEvent>>>,
    vpn_config: Arc<crate::config::Config>,
) -> Result<()> {
    let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
    let exit_peer_id = find_exit_peer_key(&vpn_config.peers)?;
    info!("SOCKS5 exit peer found: {}", exit_peer_id);

    // Spawn the receiver loop (demultiplexer)
    tokio::spawn(client_receiver_loop(
        from_tunnel_rx,
        connections.clone(),
    ));

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
                    exit_peer_id.clone(),
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

async fn handle_socks_client_connection(
    mut stream: TcpStream,
    exit_peer_id: String,
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    connections: ConnectionMap,
) -> Result<()> {
    static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(1);
    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);

    // Register channel for return traffic
    let (tx, rx) = mpsc::channel(2048); // Increased buffer for UDP bursts
    connections.write().await.insert(conn_id, tx);

    // 1. Handshake (Auth negotiation)
    if let Err(e) = perform_socks_handshake(&mut stream).await {
        error!("Conn {}: SOCKS handshake failed: {}", conn_id, e);
        connections.write().await.remove(&conn_id);
        return Err(e);
    }

    // 2. Read Request (CMD, ATYP, DST.ADDR, DST.PORT)
    let (request_bytes, cmd) = match read_socks_request(&mut stream).await {
        Ok(res) => res,
        Err(e) => {
            error!("Conn {}: Failed to read SOCKS request: {}", conn_id, e);
            connections.write().await.remove(&conn_id);
            return Err(e);
        }
    };

    match cmd {
        0x01 => { // CMD_CONNECT (TCP)
            handle_tcp_client(conn_id, stream, request_bytes, exit_peer_id, to_tunnel_tx, rx, connections).await
        }
        0x03 => { // CMD_UDP_ASSOCIATE (UDP)
            handle_udp_client(conn_id, stream, request_bytes, exit_peer_id, to_tunnel_tx, rx, connections).await
        }
        _ => {
            warn!("Conn {}: Unsupported SOCKS command: {}", conn_id, cmd);
            // Reply Command Not Supported
            let _ = stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]).await;
            connections.write().await.remove(&conn_id);
            Ok(())
        }
    }
}

async fn handle_tcp_client(
    conn_id: u32,
    mut stream: TcpStream,
    request_bytes: Bytes,
    exit_peer_id: String,
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    mut rx: mpsc::Receiver<Bytes>,
    connections: ConnectionMap,
) -> Result<()> {
    debug!("Conn {}: TCP Connect Request", conn_id);

    // Forward request to server via Tunnel
    let mut payload = BytesMut::with_capacity(4 + request_bytes.len());
    payload.put_u32_le(conn_id);
    payload.put(request_bytes);

    let cmd = TunnelCommand::SendData {
        destination_id: exit_peer_id.clone(),
        payload: payload.freeze(),
    };
    if let Err(e) = to_tunnel_tx.send(cmd).await {
        connections.write().await.remove(&conn_id);
        return Err(e.into());
    }

    // Wait for Server Reply (Success/Fail)
    let server_reply = match rx.recv().await {
        Some(reply) => reply,
        None => {
            connections.write().await.remove(&conn_id);
            return Err(anyhow!("Connection closed by server before reply"));
        }
    };

    if let Err(e) = stream.write_all(&server_reply).await {
        connections.write().await.remove(&conn_id);
        return Err(e.into());
    }

    // Pump TCP Data
    let (mut stream_read, mut stream_write) = stream.split();
    let mut read_buf = BytesMut::with_capacity(4096);

    loop {
        tokio::select! {
            // Browser -> Tunnel
            result = stream_read.read_buf(&mut read_buf) => {
                match result {
                    Ok(0) | Err(_) => break, // EOF or Error
                    Ok(n) => {
                        let mut payload = BytesMut::with_capacity(4 + n);
                        payload.put_u32_le(conn_id);
                        payload.put_slice(&read_buf[..n]);
                        read_buf.advance(n);

                        let cmd = TunnelCommand::SendData {
                            destination_id: exit_peer_id.clone(),
                            payload: payload.freeze(),
                        };
                        if to_tunnel_tx.send(cmd).await.is_err() { break; }
                    }
                }
            },
            // Tunnel -> Browser
            Some(data) = rx.recv() => {
                if stream_write.write_all(&data).await.is_err() { break; }
            },
            else => break,
        }
    }

    connections.write().await.remove(&conn_id);
    Ok(())
}

async fn handle_udp_client(
    conn_id: u32,
    mut tcp_stream: TcpStream,
    request_bytes: Bytes, // The UDP ASSOCIATE request (contains client's UDP IP/Port)
    exit_peer_id: String,
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    mut rx: mpsc::Receiver<Bytes>,
    connections: ConnectionMap,
) -> Result<()> {
    debug!("Conn {}: UDP Associate Request", conn_id);

    // 1. Bind a local UDP socket to relay packets
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = udp_socket.local_addr()?;
    debug!("Conn {}: Bound local UDP relay at {}", conn_id, local_addr);

    // 2. Tell Client where to send UDP packets (The address we just bound)
    let reply = socks_success_reply(local_addr);
    if let Err(e) = tcp_stream.write_all(&reply).await {
        connections.write().await.remove(&conn_id);
        return Err(e.into());
    }

    // 3. Initialize Server Side (Send the UDP Associate Request to Tunnel)
    let mut payload = BytesMut::with_capacity(4 + request_bytes.len());
    payload.put_u32_le(conn_id);
    payload.put(request_bytes);

    let cmd = TunnelCommand::SendData {
        destination_id: exit_peer_id.clone(),
        payload: payload.freeze(),
    };
    if let Err(e) = to_tunnel_tx.send(cmd).await {
        connections.write().await.remove(&conn_id);
        return Err(e.into());
    }

    // 4. Wait for Server 'OK'
    match rx.recv().await {
        Some(_) => debug!("Conn {}: Server confirmed UDP setup", conn_id),
        None => {
            connections.write().await.remove(&conn_id);
            return Err(anyhow!("Server rejected UDP setup"));
        }
    };

    // 5. UDP Pump Loop
    let udp_socket = Arc::new(udp_socket);
    let udp_recv = udp_socket.clone();
    let udp_send = udp_socket.clone();

    // We don't need Arc<RwLock> here because select! is single-threaded per task.
    // A simple mutable option works perfectly and is much faster.
    let mut client_addr: Option<SocketAddr> = None;

    let mut udp_buf = [0u8; 65535]; // Max UDP size

    // Buffer for the TCP control channel check
    let mut tcp_control_buf = [0u8; 1];

    loop {
        tokio::select! {
            // A. Client (Browser/Game) -> Local UDP -> Tunnel
            res = udp_recv.recv_from(&mut udp_buf) => {
                match res {
                    Ok((n, src_addr)) => {
                        // Learn client address from the first packet
                        if client_addr.is_none() || client_addr.unwrap() != src_addr {
                            client_addr = Some(src_addr);
                        }

                        // Forward the entire SOCKS UDP frame to the tunnel
                        let mut payload = BytesMut::with_capacity(4 + n);
                        payload.put_u32_le(conn_id);
                        payload.put_slice(&udp_buf[..n]);

                        let cmd = TunnelCommand::SendData {
                            destination_id: exit_peer_id.clone(),
                            payload: payload.freeze(),
                        };
                        if to_tunnel_tx.send(cmd).await.is_err() { break; }
                    },
                    Err(_) => break,
                }
            },

            // B. Tunnel -> Local UDP -> Client
            Some(data) = rx.recv() => {
                // Send back to client IF we know who they are
                if let Some(target) = client_addr {
                    let _ = udp_send.send_to(&data, target).await;
                }
            },

            // C. TCP Control Channel Monitor
            // FIX: Use the persistent buffer defined outside the loop
            _res = tcp_stream.read(&mut tcp_control_buf) => {
                // If we read anything (even 0 bytes EOF), connection is dead or closing
                break;
            }
        }
    }

    connections.write().await.remove(&conn_id);
    Ok(())
}

async fn client_receiver_loop(
    from_tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelEvent>>>,
    connections: ConnectionMap,
) {
    info!("SOCKS client receiver loop started.");
    let mut rx_guard = from_tunnel_rx.lock().await;

    loop {
        match rx_guard.recv().await {
            Some(TunnelEvent::DataReceived { mut payload, .. }) => {
                if payload.len() < 4 { continue; }
                let conn_id = payload.get_u32_le();
                let data = payload.slice(4..);

                // Use read lock to check existence
                let map = connections.read().await;
                if let Some(tx) = map.get(&conn_id) {
                    if tx.send(data).await.is_err() {
                        // Receiver closed
                    }
                }
            }
            None => break,
        }
    }
}

async fn perform_socks_handshake(stream: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8; 257];
    let n = stream.read(&mut buf).await.context("Failed to read SOCKS handshake")?;
    if n < 3 || buf[0] != 0x05 {
        return Err(anyhow!("Invalid SOCKS5 handshake"));
    }
    stream.write_all(&[0x05, 0x00]).await.context("Failed to send SOCKS method reply")?;
    Ok(())
}

async fn read_socks_request(stream: &mut TcpStream) -> Result<(Bytes, u8)> {
    let mut buf = [0u8; 512]; // Enough for headers
    let n = stream.read(&mut buf).await.context("Failed to read SOCKS request")?;
    if n < 5 {
        return Err(anyhow!("Invalid SOCKS request"));
    }

    let cmd = buf[1];
    // buf[3] is ATYP
    let req_len = match buf[3] {
        0x01 => 10, // IPv4
        0x03 => 7 + buf[4] as usize, // Domain
        0x04 => 22, // IPv6
        _ => return Err(anyhow!("SOCKS address type not supported")),
    };

    if n < req_len {
        return Err(anyhow!("Invalid SOCKS request length"));
    }

    Ok((Bytes::copy_from_slice(&buf[..req_len]), cmd))
}

// --- SOCKS Server Mode ---

pub async fn run_socks_server_mode(
    _app_config: Arc<AppConfig>,
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    from_tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelEvent>>>,
) -> Result<()> {
    let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
    info!("SOCKS5 server mode started.");

    tokio::spawn(server_receiver_loop(
        from_tunnel_rx,
        connections,
        to_tunnel_tx,
    ));

    tokio::signal::ctrl_c().await?;
    info!("SOCKS5 server shutting down.");
    Ok(())
}

async fn server_receiver_loop(
    from_tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelEvent>>>,
    connections: ConnectionMap,
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
) {
    info!("SOCKS server receiver loop started.");
    let mut rx_guard = from_tunnel_rx.lock().await;

    loop {
        match rx_guard.recv().await {
            Some(TunnelEvent::DataReceived { mut payload, source_id }) => {
                if payload.len() < 4 { continue; }
                let conn_id = payload.get_u32_le();
                let data = payload.slice(4..);

                let connections_guard = connections.read().await;
                if let Some(tx) = connections_guard.get(&conn_id) {
                    let _ = tx.send(data).await;
                } else {
                    drop(connections_guard);
                    // New Connection!
                    let (tx, rx) = mpsc::channel(2048);
                    connections.write().await.insert(conn_id, tx);

                    tokio::spawn(handle_socks_server_connection(
                        conn_id,
                        source_id,
                        data,
                        rx,
                        to_tunnel_tx.clone(),
                        connections.clone(),
                    ));
                }
            }
            None => break,
        }
    }
}

async fn handle_socks_server_connection(
    conn_id: u32,
    source_id: String,
    first_payload: Bytes, // The SOCKS Request
    mut rx: mpsc::Receiver<Bytes>,
    to_tunnel_tx: mpsc::Sender<TunnelCommand>,
    connections: ConnectionMap,
) -> Result<()> {
    if first_payload.len() < 4 {
        connections.write().await.remove(&conn_id);
        return Err(anyhow!("Short packet"));
    }

    let cmd = first_payload[1];

    let dest_addr_str = match parse_socks_addr(&first_payload[3..]) {
        Ok(a) => a,
        Err(e) => {
            warn!("Conn {}: Bad address: {}", conn_id, e);
            connections.write().await.remove(&conn_id);
            return Err(e);
        }
    };

    if cmd == 0x01 {
        // --- TCP CONNECT ---
        debug!("Conn {}: Server connecting TCP to {}", conn_id, dest_addr_str);

        let tcp_stream = match TcpStream::connect(&dest_addr_str).await {
            Ok(s) => s,
            Err(e) => {
                send_server_reply(conn_id, &source_id, &to_tunnel_tx, 0x04, "0.0.0.0:0").await;
                connections.write().await.remove(&conn_id);
                return Err(e.into());
            }
        };

        let local = tcp_stream.local_addr().unwrap_or(SocketAddr::from(([0,0,0,0],0)));
        send_server_reply(conn_id, &source_id, &to_tunnel_tx, 0x00, &local.to_string()).await;

        let (mut dest_read, mut dest_write) = tcp_stream.into_split();
        let mut read_buf = BytesMut::with_capacity(4096);

        loop {
            tokio::select! {
                Some(data) = rx.recv() => {
                    if dest_write.write_all(&data).await.is_err() { break; }
                },
                res = dest_read.read_buf(&mut read_buf) => {
                    match res {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut payload = BytesMut::with_capacity(4 + n);
                            payload.put_u32_le(conn_id);
                            payload.put_slice(&read_buf[..n]);
                            read_buf.advance(n);

                            let cmd = TunnelCommand::SendData {
                                destination_id: source_id.clone(),
                                payload: payload.freeze(),
                            };
                            if to_tunnel_tx.send(cmd).await.is_err() { break; }
                        }
                    }
                },
                else => break,
            }
        }

    } else if cmd == 0x03 {
        // --- UDP ASSOCIATE ---
        debug!("Conn {}: Server setting up UDP Relay", conn_id);

        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = udp_socket.local_addr()?;

        send_server_reply(conn_id, &source_id, &to_tunnel_tx, 0x00, &local_addr.to_string()).await;

        let udp_socket = Arc::new(udp_socket);
        let udp_recv = udp_socket.clone();
        let udp_send = udp_socket.clone();
        let mut udp_buf = [0u8; 65535];

        loop {
            tokio::select! {
                // Tunnel -> Internet
                Some(packet) = rx.recv() => {
                    if packet.len() > 10 {
                         match parse_socks_addr(&packet[3..]) {
                             Ok(target_addr_str) => {
                                 let header_len = match packet[3] {
                                     1 => 1+4+2,
                                     3 => 1+1+packet[4] as usize+2,
                                     4 => 1+16+2,
                                     _ => 0
                                 };

                                 let payload_start = 3 + header_len;

                                 if packet.len() > payload_start {
                                     let data = &packet[payload_start..];
                                     let _ = udp_send.send_to(data, target_addr_str).await;
                                 }
                             },
                             Err(e) => debug!("Bad UDP SOCKS header: {}", e),
                         }
                    }
                },

                // Internet -> Tunnel
                res = udp_recv.recv_from(&mut udp_buf) => {
                    match res {
                        Ok((n, src_addr)) => {
                            let header = build_udp_header(src_addr);
                            let mut payload = BytesMut::with_capacity(4 + header.len() + n);
                            payload.put_u32_le(conn_id);
                            payload.put_slice(&header);
                            payload.put_slice(&udp_buf[..n]);

                            let cmd = TunnelCommand::SendData {
                                destination_id: source_id.clone(),
                                payload: payload.freeze(),
                            };
                            if to_tunnel_tx.send(cmd).await.is_err() { break; }
                        },
                        Err(_) => break,
                    }
                },
                else => break,
            }
        }
    } else {
        warn!("Conn {}: Unsupported command {}", conn_id, cmd);
    }

    connections.write().await.remove(&conn_id);
    Ok(())
}

async fn send_server_reply(
    conn_id: u32,
    dest_id: &String,
    tx: &mpsc::Sender<TunnelCommand>,
    rep: u8,
    addr_str: &str
) {
    let addr: SocketAddr = addr_str.parse().unwrap_or(SocketAddr::from(([0,0,0,0], 0)));
    let reply = socks_reply_bytes(rep, addr);

    let mut payload = BytesMut::with_capacity(4 + reply.len());
    payload.put_u32_le(conn_id);
    payload.put(reply.as_slice());

    let _ = tx.send(TunnelCommand::SendData {
        destination_id: dest_id.clone(),
        payload: payload.freeze(),
    }).await;
}

// Helpers

fn parse_socks_addr(buf: &[u8]) -> Result<String> {
    if buf.is_empty() { return Err(anyhow!("Empty address buffer")); }
    let atyp = buf[0];
    let (host, port_offset) = match atyp {
        0x01 => { // IPv4
            if buf.len() < 7 { return Err(anyhow!("Short IPv4")); }
            let addr = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            (addr.to_string(), 5)
        }
        0x03 => { // Domain
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 { return Err(anyhow!("Short Domain")); }
            let domain = std::str::from_utf8(&buf[2..2+len])?;
            (domain.to_string(), 2+len)
        }
        0x04 => { // IPv6
            if buf.len() < 19 { return Err(anyhow!("Short IPv6")); }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let addr = Ipv6Addr::from(octets);
            (format!("[{}]", addr), 17)
        }
        _ => return Err(anyhow!("Unknown ATYP {}", atyp)),
    };

    if buf.len() < port_offset + 2 { return Err(anyhow!("Missing port")); }
    let port = u16::from_be_bytes([buf[port_offset], buf[port_offset+1]]);
    Ok(format!("{}:{}", host, port))
}

fn socks_success_reply(addr: SocketAddr) -> Vec<u8> {
    socks_reply_bytes(0x00, addr)
}

fn socks_reply_bytes(rep: u8, addr: SocketAddr) -> Vec<u8> {
    let mut reply = vec![0x05, rep, 0x00];
    match addr {
        SocketAddr::V4(v4) => {
            reply.push(0x01);
            reply.extend_from_slice(&v4.ip().octets());
            reply.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            reply.push(0x04);
            reply.extend_from_slice(&v6.ip().octets());
            reply.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    reply
}

fn build_udp_header(addr: SocketAddr) -> Vec<u8> {
    let mut header = vec![0x00, 0x00, 0x00];
    match addr {
        SocketAddr::V4(v4) => {
            header.push(0x01);
            header.extend_from_slice(&v4.ip().octets());
            header.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            header.push(0x04);
            header.extend_from_slice(&v6.ip().octets());
            header.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    header
}