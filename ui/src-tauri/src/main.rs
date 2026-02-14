// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, RunEvent, WindowEvent,
};

use std::sync::Mutex;

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
fn start_sidecar(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let state = app.state::<SidecarState>();
    let mut process_lock = state.process.lock().map_err(|e| format!("sidecar state lock poisoned: {}", e))?;

    // Don't start if already running
    if process_lock.is_some() {
        return Ok(());
    }

    // Get config path from app data directory
    let config_path = app
        .path()
        .app_data_dir()?
        .join("sigil.yaml")
        .to_string_lossy()
        .to_string();

    // Start sidecar with shell plugin
    let sidecar = tauri_plugin_shell::ShellExt::shell(app)
        .sidecar("sigil")?
        .args(&["start", "--config", &config_path])
        .spawn()?;

    *process_lock = Some(sidecar);

    println!("Sigil gateway started with config: {}", config_path);
    Ok(())
}

/// Stop the Sigil gateway sidecar process
fn stop_sidecar(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let state = app.state::<SidecarState>();
    let mut process_lock = state.process.lock().map_err(|e| format!("sidecar state lock poisoned: {}", e))?;

    if let Some(mut process) = process_lock.take() {
        // CommandChild only supports kill() — graceful shutdown via API signal
        // would require the gateway to support a shutdown endpoint.
        process.kill()?;
        println!("Sigil gateway stopped");
    }

    Ok(())
}

/// Restart the Sigil gateway sidecar process
fn restart_sidecar(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
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
            &MenuItemBuilder::new("Pause Agent")
                .id("pause")
                .build(app)?,
        )
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
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
        TrayIconEvent::MenuItemClick { id, .. } => {
            match id.as_ref() {
                "open" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "pause" => {
                    // TODO: Implement agent pause via API call
                    println!("Pause agent requested");
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
            // Create tray menu
            let menu = create_tray_menu(&app.handle())?;

            // Build tray icon
            // Note: In production, use a proper icon. This is a placeholder.
            let icon = Image::from_bytes(include_bytes!("../icons/icon.png"))?;

            let _tray = TrayIconBuilder::with_id("main")
                .icon(icon)
                .menu(&menu)
                .menu_on_left_click(false)
                .title("Sigil")
                .on_tray_icon_event(|tray, event| {
                    handle_tray_event(tray.app_handle(), event);
                })
                .build(app)?;

            // Start the Sigil gateway sidecar on app launch
            let app_handle = app.handle().clone();
            std::thread::spawn(move || {
                if let Err(e) = start_sidecar(&app_handle) {
                    eprintln!("Failed to start Sigil gateway: {}", e);
                    let _ = app_handle.emit("sidecar-error", format!("Failed to start gateway: {}", e));
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Hide window instead of closing on close button
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { .. } = event {
                // Clean up sidecar on app exit
                let _ = stop_sidecar(app_handle);
            }
        });
}
