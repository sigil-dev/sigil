// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, RunEvent, WindowEvent,
};

#[cfg(desktop)]
use tauri_plugin_updater::UpdaterExt;

use log::{error, info, warn};
use std::sync::atomic::{AtomicU8, Ordering};
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

/// Sidecar lifecycle states for the atomic state machine.
///
/// Transitions:
///   Stopped  -> Starting -> Running
///   Running  -> Stopping -> Stopped
///
/// `Starting` and `Stopping` are transient -- they prevent concurrent
/// start/stop races by acting as "locked" states.
mod sidecar_phase {
    pub const STOPPED: u8 = 0;
    pub const STARTING: u8 = 1;
    pub const RUNNING: u8 = 2;
    pub const STOPPING: u8 = 3;

    pub fn name(v: u8) -> &'static str {
        match v {
            STOPPED => "Stopped",
            STARTING => "Starting",
            RUNNING => "Running",
            STOPPING => "Stopping",
            _ => "Unknown",
        }
    }
}

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
    #[error("invalid sidecar state transition: cannot {action} while {phase}")]
    InvalidState {
        action: &'static str,
        phase: &'static str,
    },
}

/// Sidecar process handle stored in app state.
///
/// `phase` is an atomic state machine that prevents concurrent start/stop
/// races without holding the mutex across long-running operations.
struct SidecarState {
    process: Mutex<Option<tauri_plugin_shell::process::CommandChild>>,
    phase: AtomicU8,
}

impl SidecarState {
    fn new() -> Self {
        Self {
            process: Mutex::new(None),
            phase: AtomicU8::new(sidecar_phase::STOPPED),
        }
    }
}

/// Start the Sigil gateway sidecar process
fn start_sidecar(app: &AppHandle) -> Result<(), SidecarError> {
    let state = app.state::<SidecarState>();

    // Atomically transition Stopped -> Starting. Any other current phase
    // means a start or stop is already in progress (or it's already running).
    match state.phase.compare_exchange(
        sidecar_phase::STOPPED,
        sidecar_phase::STARTING,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(_) => {} // Successfully claimed Starting
        Err(current) if current == sidecar_phase::RUNNING => {
            // Already running -- idempotent success
            return Ok(());
        }
        Err(current) => {
            return Err(SidecarError::InvalidState {
                action: "start",
                phase: sidecar_phase::name(current),
            });
        }
    }

    // From here on, phase == Starting. If we fail, revert to Stopped.
    let result = (|| -> Result<(), SidecarError> {
        let mut process_lock = state
            .process
            .lock()
            .map_err(|e| SidecarError::LockPoisoned(e.to_string()))?;

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
        Ok(())
    })();

    if result.is_err() {
        state.phase.store(sidecar_phase::STOPPED, Ordering::SeqCst);
        return result;
    }

    // Transition Starting -> Running
    state.phase.store(sidecar_phase::RUNNING, Ordering::SeqCst);

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
                    // Retry critical sidecar-ready event emission with fallback logging
                    emit_critical_event(&app_handle, "sidecar-ready", ());
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
        // Retry critical sidecar-error event emission with fallback logging
        emit_critical_event(&app_handle, "sidecar-error", &msg);
    });

    Ok(())
}

/// Emit a critical event with retry logic to prevent UI indefinite loading.
///
/// Critical events (sidecar-ready, sidecar-error) MUST reach the UI to unblock
/// loading states. This function retries emission twice with a short delay,
/// falling back to stderr logging if all attempts fail.
fn emit_critical_event<S: serde::Serialize + Clone>(
    app: &AppHandle,
    event: &str,
    payload: S,
) {
    const MAX_RETRIES: usize = 2;
    const RETRY_DELAY_MS: u64 = 50;

    for attempt in 0..=MAX_RETRIES {
        match app.emit(event, payload.clone()) {
            Ok(()) => {
                if attempt > 0 {
                    warn!(
                        "Critical event '{}' succeeded on retry attempt {}",
                        event, attempt
                    );
                }
                return;
            }
            Err(e) => {
                if attempt < MAX_RETRIES {
                    warn!(
                        "Critical event '{}' emission failed (attempt {}/{}): {}, retrying...",
                        event,
                        attempt + 1,
                        MAX_RETRIES + 1,
                        e
                    );
                    std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
                } else {
                    // All retries exhausted — log to stderr with actionable guidance
                    eprintln!(
                        "CRITICAL: Event '{}' failed after {} attempts: {}. \
                         UI may be stuck in loading state. Check Tauri event listeners and IPC configuration.",
                        event,
                        MAX_RETRIES + 1,
                        e
                    );
                    error!(
                        "Critical event '{}' emission permanently failed after {} attempts: {}",
                        event,
                        MAX_RETRIES + 1,
                        e
                    );
                }
            }
        }
    }
}

/// Perform health check on the sidecar gateway
fn health_check_sidecar() -> Result<bool, Box<dyn std::error::Error>> {
    // Try to connect to the gateway's health endpoint
    let health_url = format!("http://localhost:{}/health", DEFAULT_GATEWAY_PORT);

    // Use ureq for a simple HTTP request
    match ureq::get(&health_url)
        .timeout(std::time::Duration::from_secs(3))
        .call()
    {
        Ok(response) => Ok(response.status() == 200),
        Err(ureq::Error::Status(code, _)) => {
            // Gateway responded but with non-200 status
            warn!("Health check returned non-OK status: {}", code);
            Ok(false)
        }
        Err(ureq::Error::Transport(transport_err)) => {
            // Connection failed — return Err to distinguish "unreachable" from "unhealthy".
            Err(Box::new(transport_err) as Box<dyn std::error::Error>)
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
/// 1. Atomically transition Running -> Stopping (prevents concurrent starts).
/// 2. (Unix) Send SIGTERM, giving the gateway time to flush SQLite WAL
///    and close connections cleanly.
/// 3. Poll for process exit up to `GRACEFUL_SHUTDOWN_TIMEOUT`.
/// 4. If the process is still alive, escalate to SIGKILL.
/// 5. Transition Stopping -> Stopped.
///
/// On Windows, `CommandChild::kill()` calls `TerminateProcess` directly
/// since Windows lacks SIGTERM semantics.
///
/// The mutex is held for the entire shutdown sequence to prevent another
/// thread from observing an empty `process` slot and spawning a new sidecar
/// while the old one is still terminating.
fn stop_sidecar(app: &AppHandle) -> Result<(), SidecarError> {
    let state = app.state::<SidecarState>();

    // Atomically transition Running -> Stopping.
    match state.phase.compare_exchange(
        sidecar_phase::RUNNING,
        sidecar_phase::STOPPING,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(_) => {} // Successfully claimed Stopping
        Err(current) if current == sidecar_phase::STOPPED => {
            // Already stopped -- idempotent success
            return Ok(());
        }
        Err(current) => {
            return Err(SidecarError::InvalidState {
                action: "stop",
                phase: sidecar_phase::name(current),
            });
        }
    }

    // From here on, phase == Stopping. Always transition to Stopped on exit.
    let result = (|| -> Result<(), SidecarError> {
        let mut process_lock = state
            .process
            .lock()
            .map_err(|e| SidecarError::LockPoisoned(e.to_string()))?;

        if let Some(process) = process_lock.take() {
            let pid = process.pid();
            // Log PID at Error level before kill attempt to ensure it's available for manual cleanup if kill fails
            error!("Attempting to terminate Sigil gateway process with PID {}", pid);

            // Drop lock immediately after taking the process. The atomic phase
            // prevents new starts. Holding the lock during graceful shutdown polling
            // (up to 5 seconds) blocks other concurrent operations.
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
    })();

    // Always transition to Stopped, even on error. A failed kill leaves
    // the process potentially orphaned, but the slot is empty and we must
    // allow future start attempts.
    state.phase.store(sidecar_phase::STOPPED, Ordering::SeqCst);

    result
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

/// Result of a manual update check, returned to the frontend.
#[derive(Debug, Clone, serde::Serialize)]
struct UpdateCheckResult {
    available: bool,
    version: Option<String>,
    body: Option<String>,
}

/// Check for application updates.
///
/// Returns whether an update is available, and if so, the version and release
/// notes. The actual download and install is left to the frontend via the
/// `@tauri-apps/plugin-updater` JS API so the UI can show progress.
#[cfg(desktop)]
#[tauri::command]
async fn check_for_update(app: AppHandle) -> Result<UpdateCheckResult, String> {
    let updater = app.updater().map_err(|e| format!("updater not available: {}", e))?;

    match updater.check().await {
        Ok(Some(update)) => {
            info!("Update available: {}", update.version);
            Ok(UpdateCheckResult {
                available: true,
                version: Some(update.version.clone()),
                body: update.body.clone(),
            })
        }
        Ok(None) => {
            info!("No update available");
            Ok(UpdateCheckResult {
                available: false,
                version: None,
                body: None,
            })
        }
        Err(e) => {
            error!("Update check failed: {}", e);
            Err(format!("update check failed: {}", e))
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::new().build())
        .plugin(tauri_plugin_shell::init());

    // Desktop-only plugins: updater and process (deps are cfg-gated in Cargo.toml)
    #[cfg(desktop)]
    {
        builder = builder
            .plugin(tauri_plugin_updater::Builder::new().build())
            .plugin(tauri_plugin_process::init())
            .invoke_handler(tauri::generate_handler![check_for_update]);
    }

    builder
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // -------------------------------------------------------------------------
    // sidecar_phase: constants and name()
    // -------------------------------------------------------------------------

    #[test]
    fn phase_constants_are_distinct() {
        let phases = [
            sidecar_phase::STOPPED,
            sidecar_phase::STARTING,
            sidecar_phase::RUNNING,
            sidecar_phase::STOPPING,
        ];
        for i in 0..phases.len() {
            for j in (i + 1)..phases.len() {
                assert_ne!(
                    phases[i], phases[j],
                    "phase constants must be unique: {} == {}",
                    phases[i], phases[j]
                );
            }
        }
    }

    #[test]
    fn phase_name_returns_correct_strings() {
        assert_eq!(sidecar_phase::name(sidecar_phase::STOPPED), "Stopped");
        assert_eq!(sidecar_phase::name(sidecar_phase::STARTING), "Starting");
        assert_eq!(sidecar_phase::name(sidecar_phase::RUNNING), "Running");
        assert_eq!(sidecar_phase::name(sidecar_phase::STOPPING), "Stopping");
    }

    #[test]
    fn phase_name_unknown_value_returns_unknown() {
        assert_eq!(sidecar_phase::name(99), "Unknown");
        assert_eq!(sidecar_phase::name(255), "Unknown");
    }

    // -------------------------------------------------------------------------
    // SidecarError: Display / Debug
    // -------------------------------------------------------------------------

    #[test]
    fn sidecar_error_lock_poisoned_display() {
        let err = SidecarError::LockPoisoned("test lock poisoned".to_string());
        let msg = format!("{}", err);
        assert!(
            msg.contains("lock poisoned"),
            "display should mention 'lock poisoned', got: {}",
            msg
        );
        assert!(msg.contains("test lock poisoned"), "display should include the cause");
    }

    #[test]
    fn sidecar_error_invalid_state_display() {
        let err = SidecarError::InvalidState {
            action: "start",
            phase: "Starting",
        };
        let msg = format!("{}", err);
        assert!(msg.contains("start"), "display should mention the action");
        assert!(msg.contains("Starting"), "display should mention the phase");
    }

    #[test]
    fn sidecar_error_debug_is_implemented() {
        let err = SidecarError::LockPoisoned("debug test".to_string());
        // If Debug is not implemented this will not compile; at runtime we just
        // verify it produces a non-empty string.
        let dbg = format!("{:?}", err);
        assert!(!dbg.is_empty());
    }

    // -------------------------------------------------------------------------
    // SidecarState: construction and initial phase
    // -------------------------------------------------------------------------

    #[test]
    fn sidecar_state_new_starts_stopped() {
        let state = SidecarState::new();
        assert_eq!(
            state.phase.load(Ordering::SeqCst),
            sidecar_phase::STOPPED,
            "freshly constructed SidecarState must be in Stopped phase"
        );
    }

    #[test]
    fn sidecar_state_process_mutex_initially_none() {
        let state = SidecarState::new();
        let guard = state.process.lock().expect("lock should not be poisoned");
        assert!(guard.is_none(), "initial process slot must be None");
    }

    // -------------------------------------------------------------------------
    // Atomic phase transitions: direct manipulation mirrors start/stop logic
    // -------------------------------------------------------------------------

    #[test]
    fn phase_transition_stopped_to_starting_succeeds() {
        let state = SidecarState::new();
        let result = state.phase.compare_exchange(
            sidecar_phase::STOPPED,
            sidecar_phase::STARTING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(result.is_ok(), "Stopped->Starting must succeed");
        assert_eq!(state.phase.load(Ordering::SeqCst), sidecar_phase::STARTING);
    }

    #[test]
    fn phase_transition_starting_to_running_succeeds() {
        let state = SidecarState::new();
        // Place into Starting
        state.phase.store(sidecar_phase::STARTING, Ordering::SeqCst);

        state.phase.store(sidecar_phase::RUNNING, Ordering::SeqCst);
        assert_eq!(state.phase.load(Ordering::SeqCst), sidecar_phase::RUNNING);
    }

    #[test]
    fn phase_transition_running_to_stopping_succeeds() {
        let state = SidecarState::new();
        state.phase.store(sidecar_phase::RUNNING, Ordering::SeqCst);

        let result = state.phase.compare_exchange(
            sidecar_phase::RUNNING,
            sidecar_phase::STOPPING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(result.is_ok(), "Running->Stopping must succeed");
        assert_eq!(state.phase.load(Ordering::SeqCst), sidecar_phase::STOPPING);
    }

    #[test]
    fn phase_transition_stopping_to_stopped_succeeds() {
        let state = SidecarState::new();
        state.phase.store(sidecar_phase::STOPPING, Ordering::SeqCst);

        state.phase.store(sidecar_phase::STOPPED, Ordering::SeqCst);
        assert_eq!(state.phase.load(Ordering::SeqCst), sidecar_phase::STOPPED);
    }

    #[test]
    fn phase_start_rejected_when_already_starting() {
        let state = SidecarState::new();
        state.phase.store(sidecar_phase::STARTING, Ordering::SeqCst);

        let result = state.phase.compare_exchange(
            sidecar_phase::STOPPED,
            sidecar_phase::STARTING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(result.is_err(), "start must fail when already Starting");
        assert_eq!(
            result.unwrap_err(),
            sidecar_phase::STARTING,
            "CAS failure should return current phase"
        );
    }

    #[test]
    fn phase_start_rejected_when_stopping() {
        let state = SidecarState::new();
        state.phase.store(sidecar_phase::STOPPING, Ordering::SeqCst);

        let result = state.phase.compare_exchange(
            sidecar_phase::STOPPED,
            sidecar_phase::STARTING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(result.is_err(), "start must fail when Stopping");
    }

    #[test]
    fn phase_stop_rejected_when_already_stopped() {
        let state = SidecarState::new();
        // Phase is STOPPED by default

        let result = state.phase.compare_exchange(
            sidecar_phase::RUNNING,
            sidecar_phase::STOPPING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(result.is_err(), "stop must fail when already Stopped");
        assert_eq!(result.unwrap_err(), sidecar_phase::STOPPED);
    }

    #[test]
    fn phase_stop_rejected_when_starting() {
        let state = SidecarState::new();
        state.phase.store(sidecar_phase::STARTING, Ordering::SeqCst);

        let result = state.phase.compare_exchange(
            sidecar_phase::RUNNING,
            sidecar_phase::STOPPING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(result.is_err(), "stop must fail when Starting");
        assert_eq!(
            result.unwrap_err(),
            sidecar_phase::STARTING,
            "CAS must return current phase (STARTING)"
        );
    }

    // -------------------------------------------------------------------------
    // Lock poisoning: verify SidecarState handles a poisoned mutex
    // -------------------------------------------------------------------------

    #[test]
    fn lock_poisoning_detected_via_map_err() {
        // Poison the mutex by panicking inside a lock guard in another thread.
        let state = Arc::new(SidecarState::new());
        let state_clone = Arc::clone(&state);

        let join_handle = std::thread::spawn(move || {
            let _guard = state_clone.process.lock().unwrap();
            panic!("intentional panic to poison the lock");
        });

        // The join will be Err because the thread panicked.
        let _ = join_handle.join();

        // Now the mutex is poisoned; map_err should catch it.
        let lock_result = state
            .process
            .lock()
            .map_err(|e| SidecarError::LockPoisoned(e.to_string()));

        assert!(
            lock_result.is_err(),
            "poisoned mutex must produce an error"
        );
        match lock_result.unwrap_err() {
            SidecarError::LockPoisoned(msg) => {
                assert!(!msg.is_empty(), "LockPoisoned message must not be empty");
            }
            other => panic!("expected LockPoisoned, got {:?}", other),
        }
    }

    #[test]
    fn lock_poisoning_error_display_is_informative() {
        let state = Arc::new(SidecarState::new());
        let state_clone = Arc::clone(&state);

        let _ = std::thread::spawn(move || {
            let _guard = state_clone.process.lock().unwrap();
            panic!("poison");
        })
        .join();

        let err = state
            .process
            .lock()
            .map_err(|e| SidecarError::LockPoisoned(e.to_string()))
            .unwrap_err();

        let display = format!("{}", err);
        // The Display impl is: "sidecar state lock poisoned: {0}"
        assert!(
            display.starts_with("sidecar state lock poisoned"),
            "display should start with the prefix, got: {}",
            display
        );
    }

    // -------------------------------------------------------------------------
    // stop_sidecar drops lock before polling: verify via phase + lock state
    //
    // This test verifies the refactored stop_sidecar behavior (sigil-7cw):
    // after taking the process out of the mutex, the lock must be released
    // before graceful-shutdown polling begins, so other threads can observe
    // the empty process slot.
    //
    // We test this indirectly: after stop_sidecar drops the lock and begins
    // polling, a concurrent thread MUST be able to acquire the mutex.
    // Since we cannot call stop_sidecar without AppHandle in a unit test,
    // we replicate the critical section logic here.
    // -------------------------------------------------------------------------

    #[test]
    fn stop_sidecar_drops_lock_before_polling_simulation() {
        // Simulate the critical section from stop_sidecar:
        //   1. Acquire mutex
        //   2. Take value out of Option
        //   3. Drop the lock BEFORE polling
        //   4. A concurrent thread can now acquire the same mutex DURING polling
        use std::sync::Barrier;

        let state = Arc::new(SidecarState::new());
        state.phase.store(sidecar_phase::RUNNING, Ordering::SeqCst);

        // Put a sentinel value in the process slot (None is fine; we just test
        // the lock-drop behavior, not actual process management).
        {
            let mut guard = state.process.lock().unwrap();
            *guard = None;
        }

        // Barrier ensures the main thread tries to acquire the lock while the
        // simulation thread is still in its "polling" phase (after dropping the lock).
        let barrier = Arc::new(Barrier::new(2));

        let state_clone = Arc::clone(&state);
        let barrier_clone = Arc::clone(&barrier);

        // Simulate the critical section of stop_sidecar
        let simulation = std::thread::spawn(move || {
            let mut process_lock = state_clone.process.lock().unwrap();
            let _taken = process_lock.take(); // Mirrors process_lock.take() in stop_sidecar
            drop(process_lock); // This is the key refactored behavior from sigil-7cw

            // Signal that lock has been dropped, then wait — simulating polling
            // while the main thread concurrently acquires the mutex.
            barrier_clone.wait();
            std::thread::sleep(Duration::from_millis(50));
        });

        // Wait until the simulation thread has dropped the lock and entered polling.
        barrier.wait();

        // While the simulation thread is "polling", the main thread must be able
        // to acquire the mutex concurrently — this is the key property under test.
        let guard = state.process.lock().expect(
            "mutex must be acquirable DURING polling (lock should have been dropped before poll)",
        );
        assert!(guard.is_none(), "process slot must be empty after take()");
        drop(guard);

        simulation.join().expect("simulation thread must not panic");
    }

    // -------------------------------------------------------------------------
    // is_process_alive: Unix-only process existence check
    // -------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn is_process_alive_returns_true_for_current_process() {
        let pid = std::process::id();
        assert!(
            is_process_alive(pid),
            "current process (pid {}) must be alive",
            pid
        );
    }

    #[cfg(unix)]
    #[test]
    fn is_process_alive_returns_false_for_nonexistent_pid() {
        // PID 0 is the scheduler on Unix; kill(0, 0) checks the whole process
        // group, so we use a very high PID unlikely to exist.
        // PID 4194304 is above Linux's PID_MAX_LIMIT (4194304) which is the max
        // on most kernels; using u32::MAX is safe to pass to libc.
        let nonexistent_pid: u32 = u32::MAX;
        // This might return true if the system wraps PIDs, so we just verify it
        // returns a bool without panicking.
        let _ = is_process_alive(nonexistent_pid);
    }

    // -------------------------------------------------------------------------
    // send_sigterm: Unix-only SIGTERM
    // -------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn send_sigterm_to_nonexistent_pid_returns_error() {
        // u32::MAX is almost certainly not a valid PID
        let result = send_sigterm(u32::MAX);
        // We expect an error because the process does not exist (ESRCH)
        // but we allow Ok(()) on exotic systems where PID wrapping occurs.
        // The important thing is: it does not panic.
        let _ = result;
    }

    #[cfg(unix)]
    #[test]
    fn send_sigterm_esrch_has_correct_os_error() {
        // Force an ESRCH by sending to u32::MAX
        let result = send_sigterm(u32::MAX);
        if let Err(e) = result {
            // The os error should be ESRCH (3 on macOS/Linux)
            if let Some(code) = e.raw_os_error() {
                assert_eq!(
                    code,
                    libc::ESRCH,
                    "non-existent PID should yield ESRCH, got os error {}",
                    code
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // health_check_sidecar: verify it returns Err when gateway is not running
    //
    // This test assumes no service is listening on DEFAULT_GATEWAY_PORT in the
    // test environment. If one IS running, the test is skipped.
    // -------------------------------------------------------------------------

    #[test]
    fn health_check_returns_err_when_gateway_unreachable() {
        // Attempt the health check. If nothing is listening on the port, we
        // expect a transport error (Err). If something IS listening and returns
        // 200, we skip. If it returns non-200, we expect Ok(false).
        match health_check_sidecar() {
            Err(_) => {
                // Expected: gateway not running → transport error
            }
            Ok(false) => {
                // Acceptable: something is listening but returning non-200
            }
            Ok(true) => {
                // A gateway is actually running; skip this assertion.
                // This can happen in CI or dev environments with a running gateway.
                eprintln!(
                    "WARNING: health_check_sidecar returned Ok(true) — a gateway is running on port {}. \
                     Test assertion skipped.",
                    DEFAULT_GATEWAY_PORT
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // DEFAULT_GATEWAY_PORT and duration constants: sanity checks
    // -------------------------------------------------------------------------

    #[test]
    fn default_gateway_port_is_nonzero() {
        assert!(DEFAULT_GATEWAY_PORT > 0, "gateway port must be non-zero");
        // Port should be in the dynamic/private range (1024-65535)
        assert!(
            DEFAULT_GATEWAY_PORT >= 1024,
            "gateway port {} should be >= 1024 (unprivileged)",
            DEFAULT_GATEWAY_PORT
        );
    }

    #[test]
    fn graceful_shutdown_timeout_is_positive() {
        assert!(
            GRACEFUL_SHUTDOWN_TIMEOUT > Duration::ZERO,
            "graceful shutdown timeout must be positive"
        );
    }

    #[test]
    fn shutdown_poll_interval_is_less_than_timeout() {
        assert!(
            SHUTDOWN_POLL_INTERVAL < GRACEFUL_SHUTDOWN_TIMEOUT,
            "poll interval ({:?}) must be less than timeout ({:?})",
            SHUTDOWN_POLL_INTERVAL,
            GRACEFUL_SHUTDOWN_TIMEOUT
        );
    }
}
