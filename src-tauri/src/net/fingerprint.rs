//! Lightweight plaintext service fingerprinting (banner grabbing).
//!
//! Once a host's open ports are known, we connect to a few well-known ones and
//! read either the greeting the service sends on connect (SSH, FTP, SMTP…) or
//! an HTTP `Server:` header. This identifies the actual software/version behind
//! a port ("nginx/1.24.0", "OpenSSH_8.9p1"). HTTPS/TLS ports are skipped to
//! keep this dependency-free.

use crate::model::ServiceBanner;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

const FP_TIMEOUT: Duration = Duration::from_millis(700);
const MAX_FP_PORTS: usize = 6;

/// Ports we speak HTTP to (send a HEAD, read the `Server` header).
const HTTP_PORTS: &[u16] = &[80, 3000, 5000, 8000, 8080, 8081, 8123, 8888, 9000, 9090];
/// Ports whose service sends a greeting banner immediately on connect.
const BANNER_PORTS: &[u16] = &[21, 22, 25, 110, 143];

/// Fingerprint a host's fingerprintable open ports, concurrently.
pub async fn fingerprint(ip: Ipv4Addr, open_ports: &[u16]) -> Vec<ServiceBanner> {
    let targets: Vec<u16> = open_ports
        .iter()
        .copied()
        .filter(|p| HTTP_PORTS.contains(p) || BANNER_PORTS.contains(p))
        .take(MAX_FP_PORTS)
        .collect();

    let mut set: JoinSet<Option<ServiceBanner>> = JoinSet::new();
    for port in targets {
        set.spawn(async move {
            grab(ip, port)
                .await
                .map(|product| ServiceBanner { port, product })
        });
    }

    let mut out = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(banner)) = joined {
            out.push(banner);
        }
    }
    out.sort_by_key(|b| b.port);
    out
}

async fn grab(ip: Ipv4Addr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let mut stream = tokio::time::timeout(FP_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let is_http = HTTP_PORTS.contains(&port);
    if is_http {
        let req = format!(
            "HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: MeshOS\r\nConnection: close\r\n\r\n"
        );
        tokio::time::timeout(FP_TIMEOUT, stream.write_all(req.as_bytes()))
            .await
            .ok()?
            .ok()?;
    }

    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(FP_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let text = String::from_utf8_lossy(&buf[..n]);

    if is_http {
        for line in text.lines() {
            if line.to_ascii_lowercase().starts_with("server:") {
                let val = line.splitn(2, ':').nth(1).unwrap_or("").trim();
                if !val.is_empty() {
                    return Some(val.chars().take(60).collect());
                }
            }
        }
        let status = text.lines().next().unwrap_or("").trim();
        return status.starts_with("HTTP/").then(|| status.chars().take(60).collect());
    }

    // Greeting banner: first non-empty line, control chars stripped, capped.
    let line = text.lines().find(|l| !l.trim().is_empty())?.trim();
    let clean: String = line.chars().filter(|c| !c.is_control()).take(70).collect();
    (!clean.is_empty()).then_some(clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fingerprints_loopback_services() {
        // On this host, 22 (ssh) and 80 (a web server) are typically open.
        let banners = fingerprint(Ipv4Addr::LOCALHOST, &[22, 80, 443]).await;
        for b in &banners {
            println!("port {} -> {}", b.port, b.product);
        }
    }
}
