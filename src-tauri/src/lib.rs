//! MeshOS systems backend: LAN discovery, device classification, and on-device
//! anomaly detection, exposed to the webview over Tauri IPC.

mod ai;
mod commands;
mod model;
mod net;
mod state;

use state::AppState;
use std::sync::Arc;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Arc::new(AppState::new()))
        .invoke_handler(tauri::generate_handler![
            commands::list_interfaces,
            commands::get_devices,
            commands::start_lan_scan,
            commands::stop_lan_scan,
            commands::rescan,
            commands::acknowledge_anomaly,
            commands::list_local_services,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the MeshOS application");
}
