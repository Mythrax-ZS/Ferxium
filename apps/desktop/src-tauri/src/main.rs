#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod bridge;
mod service;
use ferxium_core::{Action, ScanKind, ScanRequest};
use tauri::{
    Manager,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            bridge::service_status,
            bridge::service_action
        ])
        .setup(|app| {
            if let Err(error) = service::start_companion() {
                eprintln!("Could not start the current-user protection service: {error}");
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
            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("FerXium · Local-first protection")
                .on_menu_event(|app, event| {
                    let action = match event.id.as_ref() {
                        "open" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
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
                            if let Err(error) = bridge::send_action(action).await {
                                use tauri::Emitter;
                                let _ = app.emit("service-error", error);
                            }
                        });
                    }
                })
                .build(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Unable to run FerXium desktop");
}
