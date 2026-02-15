// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, RunEvent, WindowEvent,
};

use log::{error, info, warn};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default gateway port, matching the TypeScript client's API_BASE default.
/// MUST match: ui/src/lib/api/client.ts API_BASE port
const DEFAULT_GATEWAY_PORT: u16 = 18789;

/// Timeout for graceful shutdown (SIGTERM) before escalating to SIGKILL.
/// 5 seconds gives SQLite enough time to flush WAL and close connections.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval when waiting for process to exit after SIGTERM.
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(100);

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
    KillFailed(tauri_plugin_shell::Error),
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
        .join("sigil.yaml");
    let config_path_str = config_path.to_str().ok_or_else(|| {
        SidecarError::SpawnFailed(tauri_plugin_shell::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "config path contains non-UTF8 characters",
        )))
    })?;

    // Start sidecar with shell plugin
    let sidecar = tauri_plugin_shell::ShellExt::shell(app)
        .sidecar("sigil")
        .map_err(SidecarError::SpawnFailed)?
        .args(&["start", "--config", config_path_str])
        .spawn()
        .map_err(SidecarError::SpawnFailed)?;

    *process_lock = Some(sidecar);

    info!("Sigil gateway started with config: {}", config_path_str);

    // Health check: verify the gateway is running with 3 attempts (sleeps of 1s, 2s, 4s; total ~7s)
    let app_handle = app.clone();
    std::thread::spawn(move || {
        let delays = [1000u64, 2000, 4000];

        for (attempt, delay_ms) in delays.iter().enumerate() {
            std::thread::sleep(std::time::Duration::from_millis(*delay_ms));

            // Emit checking event before each attempt
            if let Err(e) = app_handle.emit(
                "sidecar-checking",
                format!("Health check attempt {}/{}", attempt + 1, delays.len()),
            ) {
                warn!("Failed to emit sidecar-checking: {}", e);
            }

            match health_check_sidecar() {
                Ok(true) => {
                    info!(
                        "Sigil gateway health check passed (attempt {})",
                        attempt + 1
                    );
                    if let Err(e) = app_handle.emit("sidecar-ready", ()) {
                        error!("Failed to emit sidecar-ready: {}", e);
                    }
                    return;
                }
                Ok(false) => {
                    warn!(
                        "Health check attempt {}/{} failed - not responding",
                        attempt + 1,
                        delays.len()
                    );
                    if let Err(e) = app_handle.emit(
                        "sidecar-retry",
                        format!(
                            "Attempt {}/{} failed — not responding",
                            attempt + 1,
                            delays.len()
                        ),
                    ) {
                        warn!("Failed to emit sidecar-retry: {}", e);
                    }
                }
                Err(e) => {
                    error!(
                        "Health check attempt {}/{} error: {}",
                        attempt + 1,
                        delays.len(),
                        e
                    );
                    if let Err(emit_err) = app_handle.emit(
                        "sidecar-retry",
                        format!("Attempt {}/{} error: {}", attempt + 1, delays.len(), e),
                    ) {
                        warn!("Failed to emit sidecar-retry: {}", emit_err);
                    }
                }
            }
        }

        let msg = format!(
            "Sigil gateway failed health check after {} attempts",
            delays.len()
        );
        error!("{}", msg);
        if let Err(e) = app_handle.emit("sidecar-error", &msg) {
            error!("Failed to emit sidecar-error: {}", e);
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
            warn!("Health check returned non-OK status: {}", code);
            Ok(false)
        }
        Err(ureq::Error::Transport(_)) => {
            // Connection failed - gateway not running
            Ok(false)
        }
    }
}

/// Check whether a process is still running by PID.
///
/// On Unix, sends signal 0 which checks for process existence without
/// actually delivering a signal. Returns `true` if the process exists.
#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) is a standard POSIX existence check.
    // Returns 0 if process exists, -1 with ESRCH if not.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(windows)]
fn is_process_alive(_pid: u32) -> bool {
    // On Windows we cannot cheaply poll; rely on kill() timeout.
    true
}

/// Send SIGTERM to a process by PID (Unix only).
///
/// Returns `Ok(())` if the signal was delivered, `Err` if the process
/// doesn't exist or we lack permission.
#[cfg(unix)]
fn send_sigterm(pid: u32) -> Result<(), std::io::Error> {
    // SAFETY: Sending SIGTERM to a known child PID we spawned.
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Stop the Sigil gateway sidecar process with graceful shutdown.
///
/// Shutdown sequence:
/// 1. (Unix) Send SIGTERM, giving the gateway time to flush SQLite WAL
///    and close connections cleanly.
/// 2. Poll for process exit up to `GRACEFUL_SHUTDOWN_TIMEOUT`.
/// 3. If the process is still alive, escalate to SIGKILL.
///
/// On Windows, `CommandChild::kill()` calls `TerminateProcess` directly
/// since Windows lacks SIGTERM semantics.
fn stop_sidecar(app: &AppHandle) -> Result<(), SidecarError> {
    let state = app.state::<SidecarState>();
    let mut process_lock = state
        .process
        .lock()
        .map_err(|e| SidecarError::LockPoisoned(e.to_string()))?;

    if let Some(process) = process_lock.take() {
        let pid = process.pid();
        // Log PID at Error level before kill attempt to ensure it's available for manual cleanup if kill fails
        error!("Attempting to terminate Sigil gateway process with PID {}", pid);

        // Drop the lock before entering the potentially long polling loop.
        // We've already taken ownership of the process via take().
        drop(process_lock);

        // Phase 1: Attempt graceful shutdown with SIGTERM (Unix only)
        #[cfg(unix)]
        {
            match send_sigterm(pid) {
                Ok(()) => {
                    info!(
                        "Sent SIGTERM to gateway (pid {}), waiting for graceful exit",
                        pid
                    );

                    let deadline = Instant::now() + GRACEFUL_SHUTDOWN_TIMEOUT;
                    while Instant::now() < deadline {
                        if !is_process_alive(pid) {
                            info!("Gateway (pid {}) exited gracefully after SIGTERM", pid);
                            return Ok(());
                        }
                        std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
                    }

                    warn!(
                        "Gateway (pid {}) did not exit within {}s after SIGTERM, sending SIGKILL",
                        pid,
                        GRACEFUL_SHUTDOWN_TIMEOUT.as_secs()
                    );
                }
                Err(e) => {
                    // ESRCH (no such process) means it already exited
                    if e.raw_os_error() == Some(libc::ESRCH) {
                        info!("Gateway (pid {}) already exited", pid);
                        return Ok(());
                    }
                    warn!(
                        "Failed to send SIGTERM to gateway (pid {}): {}, falling back to SIGKILL",
                        pid, e
                    );
                }
            }
        }

        // Phase 2: Forceful shutdown (SIGKILL on Unix, TerminateProcess on Windows)
        if let Err(kill_err) = process.kill() {
            // Log the error with PID at Error level so users can manually kill the process
            error!(
                "Failed to kill Sigil gateway process (PID {}): {}. Process may be orphaned. Manual cleanup required: kill {}",
                pid, kill_err, pid
            );
            return Err(SidecarError::KillFailed(kill_err));
        }
        info!("Sigil gateway (pid {}) terminated", pid);
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
fn create_tray_menu(
    app: &AppHandle,
) -> Result<tauri::menu::Menu<tauri::Wry>, Box<dyn std::error::Error>> {
    let menu = MenuBuilder::new(app)
        .item(&MenuItemBuilder::new("Open Sigil").id("open").build(app)?)
        .separator()
        .item(
            &MenuItemBuilder::new("Restart Gateway")
                .id("restart")
                .build(app)?,
        )
        .separator()
        .item(&MenuItemBuilder::new("Quit").id("quit").build(app)?)
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
                    error!("Failed to show window: {}", e);
                }
                if let Err(e) = window.set_focus() {
                    error!("Failed to set focus: {}", e);
                }
            }
        }
        TrayIconEvent::MenuItemClick { id, .. } => match id.as_ref() {
            "open" => {
                if let Some(window) = app.get_webview_window("main") {
                    if let Err(e) = window.show() {
                        error!("Failed to show window: {}", e);
                    }
                    if let Err(e) = window.set_focus() {
                        error!("Failed to set focus: {}", e);
                    }
                }
            }
            "restart" => {
                if let Err(e) = restart_sidecar(app) {
                    error!("Failed to restart gateway: {}", e);
                    if let Err(emit_err) = app.emit("sidecar-error", format!("Restart failed: {}", e)) {
                        error!("Failed to emit restart error notification: {}", emit_err);
                    }
                }
            }
            "quit" => {
                if let Err(e) = stop_sidecar(app) {
                    error!("Failed to stop gateway: {}", e);
                    if let Err(emit_err) = app.emit("sidecar-error", format!("Stop failed: {}", e)) {
                        error!("Failed to emit stop error notification: {}", emit_err);
                    }
                }
                app.exit(0);
            }
            _ => {}
        },
        _ => {}
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::new().build())
        .plugin(tauri_plugin_shell::init())
        .manage(SidecarState::new())
        .setup(|app| {
            // Create tray menu and icon with graceful degradation
            match create_tray_menu(&app.handle()) {
                Ok(menu) => match Image::from_bytes(include_bytes!("../icons/icon.png")) {
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
                                info!("System tray initialized");
                            }
                            Err(e) => {
                                warn!("System tray not available, continuing without tray: {}", e);
                                if let Err(emit_err) = app.emit(
                                    "tray-unavailable",
                                    format!("System tray initialization failed: {}", e),
                                ) {
                                    error!(
                                        "Failed to emit tray-unavailable notification: {}",
                                        emit_err
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to load tray icon, continuing without tray: {}", e);
                        if let Err(emit_err) = app.emit(
                            "tray-unavailable",
                            format!("Failed to load tray icon: {}", e),
                        ) {
                            error!("Failed to emit tray-unavailable notification: {}", emit_err);
                        }
                    }
                },
                Err(e) => {
                    warn!("Failed to create tray menu, continuing without tray: {}", e);
                    if let Err(emit_err) = app.emit(
                        "tray-unavailable",
                        format!("Failed to create tray menu: {}", e),
                    ) {
                        error!("Failed to emit tray-unavailable notification: {}", emit_err);
                    }
                }
            }

            // Start the Sigil gateway sidecar on app launch
            let app_handle = app.handle().clone();
            std::thread::spawn(move || {
                if let Err(e) = start_sidecar(&app_handle) {
                    error!("Failed to start Sigil gateway: {}", e);
                    if let Err(emit_err) =
                        app_handle.emit("sidecar-error", format!("Failed to start gateway: {}", e))
                    {
                        error!("Failed to emit sidecar-error: {}", emit_err);
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Hide window instead of closing on close button
                if let Err(e) = window.hide() {
                    error!("Failed to hide window: {}", e);
                }
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| panic!("error while building tauri application: {}", e))
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { .. } = event {
                // Clean up sidecar on app exit
                if let Err(e) = stop_sidecar(app_handle) {
                    error!("Failed to stop sidecar on exit: {}", e);
                }
            }
        });
}

fn main() {
    run();
}
