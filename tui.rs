use crate::tunnel::PeerMap;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
    Terminal,
};
use std::io;
use std::time::Duration;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

pub async fn run_tui(peers: PeerMap) -> Result<()> {
    // 1. Setup Terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 2. Run Loop
    let tick_rate = Duration::from_secs(1); // Update every 1 second
    let mut last_tick = std::time::Instant::now();

    loop {
        // Draw UI
        terminal.draw(|f| {
            // Use .area() instead of .size()
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
                .split(f.area());

            // Header
            let header = ratatui::widgets::Paragraph::new("RavenVeil VPN - Active Sessions")
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(header, chunks[0]);

        })?;

        // --- A. Collect Data & Update Stats (Async) ---
        let mut rows = Vec::new();
        {
            let peers_guard = peers.read().await;
            for (key, peer) in peers_guard.iter() {
                let public_key = B64.encode(key);
                let endpoint = peer.endpoint_addr.read().await.map(|a| a.to_string()).unwrap_or_else(|| "Unknown".to_string());

                // --- THE NON-BOZO STATS UPDATE ---
                // We read directly from Quinn. No packet spam.
                let mut rtt_ms = 0;
                let mut loss_pct = 0.0;
                let mut sent = 0;
                let mut recv = 0;

                if let Some(conn) = peer.connection.read().await.as_ref() {
                    let stats = conn.stats();
                    let rtt = stats.path.rtt;
                    rtt_ms = rtt.as_millis() as u64;

                    // Calculate Loss Rate based on diff from last second
                    let mut quality = peer.connection_quality.write().await;
                    let current_lost = stats.path.lost_packets;
                    let current_sent = stats.path.sent_packets;

                    let delta_lost = current_lost.saturating_sub(quality.last_lost_packets);
                    let delta_sent = current_sent.saturating_sub(quality.last_sent_packets);

                    if delta_sent > 0 {
                        loss_pct = (delta_lost as f32 / delta_sent as f32) * 100.0;
                    }

                    // Update stored stats
                    quality.latency = rtt;
                    quality.packet_loss = loss_pct;
                    quality.last_lost_packets = current_lost;
                    quality.last_sent_packets = current_sent;

                    // Traffic totals
                    sent = peer.stats.bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
                    recv = peer.stats.bytes_received.load(std::sync::atomic::Ordering::Relaxed);
                }

                // Color Logic
                let ping_color = if rtt_ms < 50 { Color::Green } else if rtt_ms < 150 { Color::Yellow } else { Color::Red };
                let loss_color = if loss_pct <= 0.1 { Color::Green } else { Color::Red };

                rows.push(Row::new(vec![
                    Cell::from(public_key[..8].to_string()), // Short key
                    Cell::from(endpoint),
                    Cell::from(format!("{} ms", rtt_ms)).style(Style::default().fg(ping_color)),
                    Cell::from(format!("{:.1}%", loss_pct)).style(Style::default().fg(loss_color)),
                    Cell::from(format!("{} / {}", format_bytes(sent), format_bytes(recv))),
                ]));
            }
        }

        // --- B. Redraw with Data ---
        terminal.draw(|f| {
            // Use .area() instead of .size()
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
                .split(f.area());

            let header_block = ratatui::widgets::Paragraph::new("RavenVeil VPN - Active Sessions (Press 'q' to quit)")
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(header_block, chunks[0]);

            let table = Table::new(rows, [
                Constraint::Length(10), // Key
                Constraint::Length(25), // Endpoint
                Constraint::Length(10), // Ping
                Constraint::Length(10), // Loss
                Constraint::Min(20),    // Traffic
            ])
                .header(Row::new(vec!["Peer", "Endpoint", "Ping", "Loss", "Traffic (Tx/Rx)"]).style(Style::default().fg(Color::Yellow)))
                .block(Block::default().borders(Borders::ALL).title("Peers"));

            f.render_widget(table, chunks[1]);
        })?;

        // 3. Input Handling
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    break;
                }
            }
        }

        // Wait for next tick
        if last_tick.elapsed() < tick_rate {
            tokio::time::sleep(tick_rate - last_tick.elapsed()).await;
        }
        last_tick = std::time::Instant::now();
    }

    // 4. Cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn format_bytes(b: u64) -> String {
    const UNIT: u64 = 1024;
    if b < UNIT { return format!("{} B", b); }
    let div = UNIT;
    if b < UNIT * UNIT { return format!("{:.1} KB", b as f64 / div as f64); }
    let div = div * UNIT;
    if b < UNIT * UNIT * UNIT { return format!("{:.1} MB", b as f64 / div as f64); }
    format!("{:.1} GB", b as f64 / (div * UNIT) as f64)
}