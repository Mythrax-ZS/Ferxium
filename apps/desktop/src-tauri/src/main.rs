#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod background;
mod bridge;
mod service;
use ferxium_core::{Action, ScanKind, ScanRequest};
use tauri::{
    Manager, WindowEvent,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

fn open_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        // A window minimized before closing must also be restored from the tray.
        if let Err(error) = window
            .show()
            .and_then(|()| window.unminimize())
            .and_then(|()| window.set_focus())
        {
            eprintln!("Could not reopen FerXium: {error}");
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if !args.iter().any(|arg| arg == "--background") {
                open_main_window(app);
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--background"]),
        ))
        .invoke_handler(tauri::generate_handler![
            bridge::service_status,
            bridge::service_action,
            background::desktop_preferences,
            background::set_desktop_preference,
            background::test_notification
        ])
        .on_window_event(|window, event| {
            if window.label() == "main"
                && let WindowEvent::CloseRequested { api, .. } = event
            {
                // Keep the webview and tray alive. Explicit tray Quit uses
                // app.exit(), which does not pass through this close handler.
                api.prevent_close();
                if let Err(error) = window.hide() {
                    eprintln!("Could not hide FerXium to the tray: {error}");
                }
            }
        })
        .setup(|app| {
            ferxium_core::privilege::require_regular_user()?;
            let args: Vec<_> = std::env::args_os().collect();
            let override_path = args
                .iter()
                .position(|arg| arg == "--data-dir")
                .map(|index| {
                    args.get(index + 1)
                        .map(std::path::PathBuf::from)
                        .ok_or("--data-dir requires an absolute path")
                })
                .transpose()?;
            if override_path
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            {
                return Err("--data-dir requires an absolute path".into());
            }
            let isolated = override_path.is_some();
            let data = override_path
                .map(Ok)
                .unwrap_or_else(ferxium_core::storage::data_dir)?;
            app.manage(background::DesktopAgent::load(data.clone(), isolated)?);
            if let Err(error) = service::start_companion(&data) {
                eprintln!("Could not start the current-user protection service: {error}");
            }
            background::start(app.handle().clone());
            if !args.iter().any(|arg| arg == "--background")
                && let Some(window) = app.get_webview_window("main")
            {
                window.show()?;
            }
            let open = MenuItem::with_id(app, "open", "Open FerXium", true, None::<&str>)?;
            let scan = MenuItem::with_id(app, "scan", "Quick scan", true, None::<&str>)?;
            let enable = MenuItem::with_id(app, "enable", "Enable monitoring", true, None::<&str>)?;
            let disable =
                MenuItem::with_id(app, "disable", "Pause monitoring", true, None::<&str>)?;
            let quit = MenuItem::with_id(
                app,
                "quit",
                "Quit desktop (service stays active)",
                true,
                None::<&str>,
            )?;
            let menu = Menu::with_items(app, &[&open, &scan, &enable, &disable, &quit])?;
            TrayIconBuilder::with_id("ferxium")
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .show_menu_on_left_click(false)
                .tooltip("FerXium · Local-first protection")
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } | TrayIconEvent::DoubleClick {
                            button: MouseButton::Left,
                            ..
                        }
                    ) {
                        open_main_window(tray.app_handle());
                    }
                })
                .on_menu_event(|app, event| {
                    let action = match event.id.as_ref() {
                        "open" => {
                            open_main_window(app);
                            None
                        }
                        "scan" => Some(Action::StartScan {
                            request: ScanRequest {
                                kind: ScanKind::Quick,
                                paths: vec![],
                            },
                        }),
                        "enable" => Some(Action::SetProtection { enabled: true }),
                        "disable" => Some(Action::SetProtection { enabled: false }),
                        "quit" => {
                            app.exit(0);
                            None
                        }
                        _ => None,
                    };
                    if let Some(action) = action {
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let data = app.state::<background::DesktopAgent>().data.clone();
                            if let Err(error) = bridge::send_action(&data, action).await {
                                use tauri::Emitter;
                                let _ = app.emit("service-error", error);
                            }
                        });
                    }
                })
                .build(app)?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Unable to build FerXium desktop")
        .run(|_app, _event| {
            // Clicking the Dock icon reopens the hidden window on macOS.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = _event {
                open_main_window(_app);
            }
        });
}
