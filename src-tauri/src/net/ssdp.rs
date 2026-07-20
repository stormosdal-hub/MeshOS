//! SSDP / UPnP discovery. Sends a multicast M-SEARCH and collects responses
//! from smart TVs, media servers, routers, and IoT devices, then makes a
//! best-effort fetch of each device's description XML for its friendly name
//! and model.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug, Default, Clone)]
pub struct SsdpInfo {
    pub model: Option<String>,
    pub server: Option<String>,
    pub services: Vec<String>,
}

const MSEARCH: &str = "M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 2\r\n\
ST: ssdp:all\r\n\r\n";

/// Multicast M-SEARCH, gather responses for `window`, then resolve names.
pub async fn discover(window: Duration) -> HashMap<Ipv4Addr, SsdpInfo> {
    let mut result: HashMap<Ipv4Addr, SsdpInfo> = HashMap::new();
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return result,
    };
    let _ = socket.set_multicast_ttl_v4(2);
    if socket
        .send_to(MSEARCH.as_bytes(), "239.255.255.250:1900")
        .await
        .is_err()
    {
        return result;
    }

    let mut locations: HashMap<Ipv4Addr, String> = HashMap::new();
    let mut buf = vec![0u8; 2048];
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                if let IpAddr::V4(ip) = src.ip() {
                    let text = String::from_utf8_lossy(&buf[..n]);
                    ingest(&mut result, &mut locations, ip, &text);
                }
            }
            _ => break,
        }
    }

    // Best-effort: fetch each device's description XML for a friendly name.
    for (ip, location) in locations {
        if let Some(model) = fetch_description(&location).await {
            result.entry(ip).or_default().model = Some(model);
        }
    }
    result
}

fn ingest(
    result: &mut HashMap<Ipv4Addr, SsdpInfo>,
    locations: &mut HashMap<Ipv4Addr, String>,
    ip: Ipv4Addr,
    text: &str,
) {
    let entry = result.entry(ip).or_default();
    if !entry.services.iter().any(|s| s == "UPnP") {
        entry.services.push("UPnP".to_string());
    }
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("server:") && entry.server.is_none() {
            let value = line.splitn(2, ':').nth(1).unwrap_or("").trim();
            if !value.is_empty() {
                entry.server = Some(value.chars().take(70).collect());
            }
        } else if lower.starts_with("location:") {
            let value = line.splitn(2, ':').nth(1).unwrap_or("").trim();
            if value.starts_with("http://") {
                locations.entry(ip).or_insert_with(|| value.to_string());
            }
        } else if lower.starts_with("st:") || lower.starts_with("nt:") {
            let value = lower.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
            let label = if value.contains("mediarenderer") {
                Some("Media Renderer")
            } else if value.contains("mediaserver") {
                Some("Media Server")
            } else if value.contains("internetgateway") {
                Some("Gateway")
            } else if value.contains("dial-multiscreen") {
                Some("DIAL")
            } else {
                None
            };
            if let Some(label) = label {
                if !entry.services.iter().any(|s| s == label) {
                    entry.services.push(label.to_string());
                }
            }
        }
    }
}

async fn fetch_description(location: &str) -> Option<String> {
    let rest = location.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(80)),
        None => (authority, 80),
    };

    let mut stream = tokio::time::timeout(
        Duration::from_millis(900),
        TcpStream::connect((host, port)),
    )
    .await
    .ok()?
    .ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tokio::time::timeout(Duration::from_millis(900), stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut body = Vec::new();
    let mut buf = [0u8; 2048];
    let read_deadline = tokio::time::Instant::now() + Duration::from_millis(1200);
    loop {
        let remaining = read_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() || body.len() > 16_384 {
            break;
        }
        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => body.extend_from_slice(&buf[..n]),
        }
    }

    let text = String::from_utf8_lossy(&body);
    extract_tag(&text, "friendlyName")
        .or_else(|| extract_tag(&text, "modelName"))
        .map(|s| s.chars().take(60).collect())
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let value = xml[start..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}
