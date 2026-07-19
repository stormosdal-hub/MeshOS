//! MAC → vendor resolution via IEEE OUI prefixes (first 24 bits).
//!
//! A curated set of common consumer/IoT vendors is embedded so the app works
//! offline with zero setup. For full coverage, drop the IEEE `oui.csv` next to
//! the binary and extend [`lookup_vendor`] to consult it — the structure here
//! (uppercase, separator-stripped 6-hex-digit prefix) matches that dataset.

/// (OUI prefix without separators, vendor name).
const OUI: &[(&str, &str)] = &[
    // Networking / gateways
    ("443839", "Ubiquiti Networks"),
    ("245A4C", "Ubiquiti Networks"),
    ("788A20", "Ubiquiti Networks"),
    ("F09FC2", "Ubiquiti Networks"),
    ("D021F9", "Ubiquiti Networks"),
    ("50C7BF", "TP-Link Technologies"),
    ("A42BB0", "TP-Link Technologies"),
    ("EC086B", "TP-Link Technologies"),
    ("C46E1F", "TP-Link Technologies"),
    ("204E7F", "Netgear"),
    ("A040A0", "Netgear"),
    ("2C3033", "Netgear"),
    ("001018", "Broadcom"),
    ("70B3D5", "IEEE Registration Authority"),
    // Espressif (ESP8266 / ESP32 microcontrollers)
    ("246F28", "Espressif Inc."),
    ("240AC4", "Espressif Inc."),
    ("30AEA4", "Espressif Inc."),
    ("7C9EBD", "Espressif Inc."),
    ("A4CF12", "Espressif Inc."),
    ("B4E62D", "Espressif Inc."),
    ("8CAAB5", "Espressif Inc."),
    ("3C6105", "Espressif Inc."),
    ("D8A01D", "Espressif Inc."),
    ("C8C9A3", "Espressif Inc."),
    // Raspberry Pi
    ("B827EB", "Raspberry Pi Foundation"),
    ("DCA632", "Raspberry Pi Trading"),
    ("E45F01", "Raspberry Pi Trading"),
    ("28CDC1", "Raspberry Pi Trading"),
    ("D83ADD", "Raspberry Pi Trading"),
    // Apple
    ("A483E7", "Apple, Inc."),
    ("F01898", "Apple, Inc."),
    ("3C0754", "Apple, Inc."),
    ("A45E60", "Apple, Inc."),
    ("BCD074", "Apple, Inc."),
    ("D0817A", "Apple, Inc."),
    ("F0DBE2", "Apple, Inc."),
    ("7CD1C3", "Apple, Inc."),
    ("14109F", "Apple, Inc."),
    // Samsung
    ("503237", "Samsung Electronics"),
    ("5CE8EB", "Samsung Electronics"),
    ("8425DB", "Samsung Electronics"),
    ("C0BDD1", "Samsung Electronics"),
    ("E8508B", "Samsung Electronics"),
    // Sony / PlayStation
    ("D83ADE", "Sony Interactive"),
    ("00041F", "Sony Interactive"),
    ("FC0FE6", "Sony Interactive"),
    ("A8E3EE", "Sony Interactive"),
    // Nintendo
    ("0009BF", "Nintendo"),
    ("E84ECE", "Nintendo"),
    ("98B6E9", "Nintendo"),
    // Microsoft / Xbox
    ("000D3A", "Microsoft"),
    ("7CED8D", "Microsoft"),
    ("C83F26", "Microsoft"),
    // Google / Nest
    ("68C63A", "Google Nest"),
    ("F4F5D8", "Google, Inc."),
    ("3C286D", "Google, Inc."),
    ("D8EB46", "Google, Inc."),
    ("1CF29A", "Google, Inc."),
    // Amazon (Echo / Fire)
    ("F0272D", "Amazon Technologies"),
    ("44650D", "Amazon Technologies"),
    ("68F728", "Amazon Technologies"),
    ("FCA667", "Amazon Technologies"),
    ("50DCE7", "Amazon Technologies"),
    // Synology / QNAP NAS
    ("001132", "Synology Inc."),
    ("0011D8", "QNAP Systems"),
    ("245EBE", "QNAP Systems"),
    // Printers
    ("30055C", "Hewlett Packard"),
    ("3CD92B", "Hewlett Packard"),
    ("9CB654", "Hewlett Packard"),
    ("002673", "Brother Industries"),
    ("008077", "Brother Industries"),
    ("001BA9", "Canon Inc."),
    ("00266C", "Seiko Epson"),
    // Cameras
    ("ACCC8E", "Axis Communications"),
    ("00408C", "Axis Communications"),
    ("C0563C", "Hangzhou Hikvision"),
    ("4419B6", "Hangzhou Hikvision"),
    ("BCAD28", "Dahua Technology"),
    ("00408A", "Reolink Innovation"),
    // Smart home
    ("D0524A", "Philips Lighting (Hue)"),
    ("001788", "Philips Lighting (Hue)"),
    ("EC1BBD", "Shelly / Allterco"),
    ("2462AB", "Espressif (Sonoff)"),
    ("50029A", "TP-Link Kasa"),
    ("D8F15B", "Espressif (Tuya)"),
    // PC / laptop vendors
    ("1C8341", "ASUSTek Computer"),
    ("2C4D54", "ASUSTek Computer"),
    ("A85E45", "ASUSTek Computer"),
    ("D850E6", "ASUSTek Computer"),
    ("00A0C9", "Intel Corporate"),
    ("3CFDFE", "Intel Corporate"),
    ("94E6F7", "Intel Corporate"),
    ("A0A8CD", "Intel Corporate"),
    ("F8B156", "Dell Inc."),
    ("D4AE52", "Dell Inc."),
    ("18DBF2", "Dell Inc."),
    ("001A6B", "Lenovo"),
    ("54EE75", "Lenovo"),
    ("E04F43", "Micro-Star (MSI)"),
    ("D8CB8A", "Micro-Star (MSI)"),
];

/// Normalize a MAC string to an uppercase 6-hex-digit OUI (first 3 octets).
fn oui_prefix(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect::<String>()
        .to_ascii_uppercase();
    if hex.len() == 6 {
        Some(hex)
    } else {
        None
    }
}

/// Resolve a MAC address to a vendor name, if the OUI is known.
pub fn lookup_vendor(mac: &str) -> Option<String> {
    let prefix = oui_prefix(mac)?;
    OUI.iter()
        .find(|(p, _)| *p == prefix)
        .map(|(_, name)| name.to_string())
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
