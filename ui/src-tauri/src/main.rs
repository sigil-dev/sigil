// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, RunEvent, WindowEvent,
};

use std::sync::Mutex;

/// Default gateway port, matching the TypeScript client's API_BASE default.
const DEFAULT_GATEWAY_PORT: u16 = 18789;

/// Errors that can occur during sidecar lifecycle management
#[derive(Debug, thiserror::Error)]
enum SidecarError {
    #[error("sidecar state lock poisoned: {0}")]
    LockPoisoned(String),
    #[error("failed to resolve app data directory: {0}")]
    AppDataDir(tauri::Error),
    #[error("failed to spawn sidecar: {0}")]
    SpawnFailed(tauri_plugin_shell::Error),
    #[error("sidecar process kill failed: {0}")]
    KillFailed(std::io::Error),
}

/// Sidecar process handle stored in app state
struct SidecarState {
    process: Mutex<Option<tauri_plugin_shell::process::CommandChild>>,
}

impl SidecarState {
    fn new() -> Self {
        Self {
            process: Mutex::new(None),
        }
    }
}

/// Start the Sigil gateway sidecar process
fn start_sidecar(app: &AppHandle) -> Result<(), SidecarError> {
    let state = app.state::<SidecarState>();
    let mut process_lock = state
        .process
        .lock()
        .map_err(|e| SidecarError::LockPoisoned(e.to_string()))?;

    // Don't start if already running
    if process_lock.is_some() {
        return Ok(());
    }

    // Get config path from app data directory
    let config_path = app
        .path()
        .app_data_dir()
        .map_err(SidecarError::AppDataDir)?
        .join("sigil.yaml")
        .to_string_lossy()
        .to_string();

    // Start sidecar with shell plugin
    let sidecar = tauri_plugin_shell::ShellExt::shell(app)
        .sidecar("sigil")
        .map_err(SidecarError::SpawnFailed)?
        .args(&["start", "--config", &config_path])
        .spawn()
        .map_err(SidecarError::SpawnFailed)?;

    *process_lock = Some(sidecar);

    println!("Sigil gateway started with config: {}", config_path);

    // Health check: verify the gateway is running with 3 attempts (1s, 2s, 4s delays)
    let app_handle = app.clone();
    std::thread::spawn(move || {
        let delays = [1000u64, 2000, 4000];

        for (attempt, delay_ms) in delays.iter().enumerate() {
            std::thread::sleep(std::time::Duration::from_millis(*delay_ms));

            // Emit checking event before each attempt
            let _ = app_handle.emit(
                "sidecar-checking",
                format!("Health check attempt {}/{}", attempt + 1, delays.len()),
            );

            match health_check_sidecar() {
                Ok(true) => {
                    println!("Sigil gateway health check passed (attempt {})", attempt + 1);
                    if let Err(e) = app_handle.emit("sidecar-ready", ()) {
                        eprintln!("Failed to emit sidecar-ready: {}", e);
                    }
                    return;
                }
                Ok(false) => {
                    eprintln!(
                        "Health check attempt {}/{} failed - not responding",
                        attempt + 1,
                        delays.len()
                    );
                    let _ = app_handle.emit(
                        "sidecar-retry",
                        format!(
                            "Attempt {}/{} failed — not responding",
                            attempt + 1,
                            delays.len()
                        ),
                    );
                }
                Err(e) => {
                    eprintln!(
                        "Health check attempt {}/{} error: {}",
                        attempt + 1,
                        delays.len(),
                        e
                    );
                    let _ = app_handle.emit(
                        "sidecar-retry",
                        format!("Attempt {}/{} error: {}", attempt + 1, delays.len(), e),
                    );
                }
            }
        }

        let msg = format!(
            "Sigil gateway failed health check after {} attempts",
            delays.len()
        );
        eprintln!("{}", msg);
        if let Err(e) = app_handle.emit("sidecar-error", &msg) {
            eprintln!("Failed to emit sidecar-error: {}", e);
        }
    });

    Ok(())
}

/// Perform health check on the sidecar gateway
fn health_check_sidecar() -> Result<bool, Box<dyn std::error::Error>> {
    // Try to connect to the gateway's health endpoint
    let health_url = format!("http://localhost:{}/health", DEFAULT_GATEWAY_PORT);

    // Use ureq for a simple HTTP request
    match ureq::get(health_url)
        .timeout(std::time::Duration::from_secs(3))
        .call()
    {
        Ok(response) => Ok(response.status() == 200),
        Err(ureq::Error::Status(code, _)) => {
            // Gateway responded but with non-200 status
            eprintln!("Health check returned non-OK status: {}", code);
            Ok(false)
        }
        Err(ureq::Error::Transport(_)) => {
            // Connection failed - gateway not running
            Ok(false)
        }
    }
}

/// Stop the Sigil gateway sidecar process
fn stop_sidecar(app: &AppHandle) -> Result<(), SidecarError> {
    let state = app.state::<SidecarState>();
    let mut process_lock = state
        .process
        .lock()
        .map_err(|e| SidecarError::LockPoisoned(e.to_string()))?;

    if let Some(mut process) = process_lock.take() {
        // Terminates the gateway process immediately. Database state depends on SQLite WAL recovery. Graceful shutdown would require the gateway to implement a /shutdown endpoint.
        process.kill().map_err(SidecarError::KillFailed)?;
        println!("Sigil gateway stopped");
    }

    Ok(())
}

/// Restart the Sigil gateway sidecar process
fn restart_sidecar(app: &AppHandle) -> Result<(), SidecarError> {
    stop_sidecar(app)?;
    std::thread::sleep(std::time::Duration::from_millis(500));
    start_sidecar(app)?;
    Ok(())
}

/// Create the system tray menu
fn create_tray_menu(app: &AppHandle) -> Result<tauri::menu::Menu<tauri::Wry>, Box<dyn std::error::Error>> {
    let menu = MenuBuilder::new(app)
        .item(
            &MenuItemBuilder::new("Open Sigil")
                .id("open")
                .build(app)?,
        )
        .separator()
        .item(
            &MenuItemBuilder::new("Restart Gateway")
                .id("restart")
                .build(app)?,
        )
        .separator()
        .item(
            &MenuItemBuilder::new("Quit")
                .id("quit")
                .build(app)?,
        )
        .build()?;

    Ok(menu)
}

/// Handle tray menu events
fn handle_tray_event(app: &AppHandle, event: TrayIconEvent) {
    match event {
        TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } => {
            // Show main window on left click
            if let Some(window) = app.get_webview_window("main") {
                if let Err(e) = window.show() {
                    eprintln!("Failed to show window: {}", e);
                }
                if let Err(e) = window.set_focus() {
                    eprintln!("Failed to set focus: {}", e);
                }
            }
        }
        TrayIconEvent::MenuItemClick { id, .. } => {
            match id.as_ref() {
                "open" => {
                    if let Some(window) = app.get_webview_window("main") {
                        if let Err(e) = window.show() {
                            eprintln!("Failed to show window: {}", e);
                        }
                        if let Err(e) = window.set_focus() {
                            eprintln!("Failed to set focus: {}", e);
                        }
                    }
                }
                "restart" => {
                    if let Err(e) = restart_sidecar(app) {
                        eprintln!("Failed to restart gateway: {}", e);
                    }
                }
                "quit" => {
                    if let Err(e) = stop_sidecar(app) {
                        eprintln!("Failed to stop gateway: {}", e);
                    }
                    app.exit(0);
                }
                _ => {}
            }
        }
        _ => {}
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(SidecarState::new())
        .setup(|app| {
            // Create tray menu and icon with graceful degradation
            match create_tray_menu(&app.handle()) {
                Ok(menu) => {
                    match Image::from_bytes(include_bytes!("../icons/icon.png")) {
                        Ok(icon) => {
                            match TrayIconBuilder::with_id("main")
                                .icon(icon)
                                .menu(&menu)
                                .menu_on_left_click(false)
                                .title("Sigil")
                                .on_tray_icon_event(|tray, event| {
                                    handle_tray_event(tray.app_handle(), event);
                                })
                                .build(app)
                            {
                                Ok(_tray) => {
                                    println!("System tray initialized");
                                }
                                Err(e) => {
                                    eprintln!("System tray not available, continuing without tray: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to load tray icon, continuing without tray: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to create tray menu, continuing without tray: {}", e);
                }
            }

            // Start the Sigil gateway sidecar on app launch
            let app_handle = app.handle().clone();
            std::thread::spawn(move || {
                if let Err(e) = start_sidecar(&app_handle) {
                    eprintln!("Failed to start Sigil gateway: {}", e);
                    if let Err(emit_err) = app_handle.emit("sidecar-error", format!("Failed to start gateway: {}", e)) {
                        eprintln!("Failed to emit sidecar-error: {}", emit_err);
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Hide window instead of closing on close button
                if let Err(e) = window.hide() {
                    eprintln!("Failed to hide window: {}", e);
                }
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { .. } = event {
                // Clean up sidecar on app exit
                if let Err(e) = stop_sidecar(app_handle) {
                    eprintln!("Failed to stop sidecar on exit: {}", e);
                }
            }
        });
}
