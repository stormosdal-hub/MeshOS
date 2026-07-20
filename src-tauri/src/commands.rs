//! Tauri IPC commands invoked from the frontend (see `src/ipc/tauri.ts`).
//! JS passes camelCase argument names, which Tauri maps to the snake_case
//! parameters here (e.g. `interfaceName` -> `interface_name`).

use crate::model::{Device, LocalService, NetInterface};
use crate::net::{discover, interface, local};
use crate::state::AppState;
use std::sync::Arc;
use tauri::{AppHandle, State};

#[tauri::command]
pub fn list_interfaces() -> Vec<NetInterface> {
    interface::list_interfaces()
}

#[tauri::command]
pub fn get_devices(state: State<'_, Arc<AppState>>) -> Vec<Device> {
    state.snapshot_devices()
}

#[tauri::command]
pub fn start_lan_scan(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    interface_name: Option<String>,
) -> Result<(), String> {
    if state.is_running() {
        return Ok(());
    }
    state.set_running(true);
    *state.selected_iface.lock().unwrap() = interface_name.clone();

    let state = state.inner().clone();
    tauri::async_runtime::spawn(async move {
        discover::scan_loop(app, state, interface_name).await;
    });
    Ok(())
}

#[tauri::command]
pub fn stop_lan_scan(state: State<'_, Arc<AppState>>) {
    state.set_running(false);
}

#[tauri::command]
pub fn rescan(app: AppHandle, state: State<'_, Arc<AppState>>) {
    let iface = state.selected_iface.lock().unwrap().clone();
    let state = state.inner().clone();
    tauri::async_runtime::spawn(async move {
        discover::scan_now(app, state, iface).await;
    });
}

#[tauri::command]
pub fn acknowledge_anomaly(state: State<'_, Arc<AppState>>, id: String) {
    state.acknowledged.lock().unwrap().insert(id);
}

/// Listening TCP servers on this machine (with owning process where available).
#[tauri::command]
pub fn list_local_services() -> Vec<LocalService> {
    local::list_local_services()
}
