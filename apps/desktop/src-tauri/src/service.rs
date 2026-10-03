//! The installed desktop starts its bundled current-user companion. No elevation,
//! PATH lookup, shell execution, or webview-controlled executable is involved.
use std::{
    io,
    process::{Command, Stdio},
};

pub fn start_companion(data: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    ferxium_core::privilege::require_regular_user()?;
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or_else(|| io::Error::other("Desktop executable has no parent directory"))?;
    let service = directory.join(if cfg!(windows) {
        "ferxium-service.exe"
    } else {
        "ferxium-service"
    });
    // Development builds can run the service separately. Installed bundles always
    // contain this sibling binary. The service lock rejects duplicate instances.
    if !service.is_file() {
        return Ok(());
    }
    let mut command = Command::new(service);
    command
        .arg("--supervise")
        .arg("--data-dir")
        .arg(data)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn()?;
    // Reap the child when it exits. Dropping the UI deliberately leaves protection
    // running; the daemon remains guarded by its per-user state lock.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
