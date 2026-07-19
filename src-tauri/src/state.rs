//! Shared application state, managed by Tauri and accessed from commands and
//! the background scan loop.

use crate::ai::anomaly::AnomalyEngine;
use crate::model::Device;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

pub struct AppState {
    running: AtomicBool,
    pub devices: Mutex<HashMap<String, Device>>,
    pub anomaly_engine: Mutex<AnomalyEngine>,
    subnet: Mutex<Option<String>>,
    pub selected_iface: Mutex<Option<String>>,
    pub acknowledged: Mutex<HashSet<String>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            devices: Mutex::new(HashMap::new()),
            anomaly_engine: Mutex::new(AnomalyEngine::new()),
            subnet: Mutex::new(None),
            selected_iface: Mutex::new(None),
            acknowledged: Mutex::new(HashSet::new()),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn set_running(&self, value: bool) {
        self.running.store(value, Ordering::SeqCst);
    }

    pub fn set_subnet(&self, subnet: Option<String>) {
        *self.subnet.lock().unwrap() = subnet;
    }

    pub fn subnet(&self) -> Option<String> {
        self.subnet.lock().unwrap().clone()
    }

    pub fn snapshot_devices(&self) -> Vec<Device> {
        self.devices.lock().unwrap().values().cloned().collect()
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
