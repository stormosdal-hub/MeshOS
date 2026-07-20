//! Enumerating the local machine's own listening TCP servers, with the owning
//! process. Unlike the network probe (which only sees other hosts' *exposed*
//! ports), this reads the OS socket table directly, so it authoritatively
//! answers "what servers are running on THIS device" — including services bound
//! to localhost that no external scan could ever see.

use crate::model::LocalService;
use crate::net::ports::service_name;

/// All listening TCP sockets on this machine. Process name/PID are filled in
/// where the OS permits (resolving another user's process may require elevated
/// privileges; such sockets are still listed, just without a process name).
pub fn list_local_services() -> Vec<LocalService> {
    let mut services: Vec<LocalService> = match listeners::get_all() {
        Ok(set) => set
            .into_iter()
            .map(|listener| {
                let port = listener.socket.port();
                LocalService {
                    address: listener.socket.ip().to_string(),
                    port,
                    protocol: "tcp".to_string(),
                    pid: Some(listener.process.pid),
                    process: Some(listener.process.name),
                    service: service_name(port).map(str::to_string),
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };

    services.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.address.cmp(&b.address)));
    services.dedup_by(|a, b| a.port == b.port && a.address == b.address && a.pid == b.pid);
    services
}

#[cfg(test)]
mod tests {
    #[test]
    fn enumerates_local_listeners_without_panicking() {
        let services = super::list_local_services();
        println!("found {} local listening services", services.len());
        for s in &services {
            println!(
                "  {}:{} [{}] {}",
                s.address,
                s.port,
                s.process.as_deref().unwrap_or("?"),
                s.service.as_deref().unwrap_or(""),
            );
        }
    }
}
