//! MAC → vendor resolution via the full IEEE OUI space (24-bit prefixes).
//!
//! The complete vendor table (`oui_db.tsv`, ~39k entries derived from the
//! Wireshark manufacturer database) is embedded at build time and parsed once
//! into a lookup map, so resolution is offline, authoritative, and covers the
//! long tail of vendors — not just a curated handful.
//!
//! Regenerate with: `scripts/gen-oui.sh` (downloads the latest DB).

use std::collections::HashMap;
use std::sync::OnceLock;

const OUI_DB_RAW: &str = include_str!("oui_db.tsv");
static OUI_DB: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();

fn db() -> &'static HashMap<u32, &'static str> {
    OUI_DB.get_or_init(|| {
        let mut map = HashMap::with_capacity(40_000);
        for line in OUI_DB_RAW.lines() {
            if let Some((hex, vendor)) = line.split_once('\t') {
                if let Ok(prefix) = u32::from_str_radix(hex, 16) {
                    map.insert(prefix, vendor);
                }
            }
        }
        map
    })
}

/// The first 24 bits of a MAC as a u32, ignoring any separators.
fn oui_prefix(mac: &str) -> Option<u32> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect();
    if hex.len() == 6 {
        u32::from_str_radix(&hex, 16).ok()
    } else {
        None
    }
}

/// Resolve a MAC address to a vendor name, if the OUI is registered.
pub fn lookup_vendor(mac: &str) -> Option<String> {
    let prefix = oui_prefix(mac)?;
    db().get(&prefix).map(|v| v.to_string())
}

/// True for locally-administered / random MACs (the U/L bit is set), which
/// modern phones use for privacy and which never carry a real vendor OUI.
pub fn is_locally_administered(mac: &str) -> bool {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 2 {
        return false;
    }
    if let Ok(first_octet) = u8::from_str_radix(&hex[0..2], 16) {
        first_octet & 0b0000_0010 != 0
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_vendors() {
        assert!(lookup_vendor("a4:83:e7:00:00:01").unwrap().contains("Apple"));
        assert!(lookup_vendor("24:6F:28:aa:bb:cc")
            .unwrap()
            .contains("Espressif"));
        assert!(lookup_vendor("B8:27:EB:12:34:56")
            .unwrap()
            .contains("Raspberry"));
        assert!(lookup_vendor("zz").is_none());
        println!("OUI table entries: {}", db().len());
    }
}
