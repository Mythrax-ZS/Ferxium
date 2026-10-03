fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "service_status",
            "service_action",
            "desktop_preferences",
            "set_desktop_preference",
            "test_notification",
        ]),
    ))
    .expect("Tauri build failed");
}
