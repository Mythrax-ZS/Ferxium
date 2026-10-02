mod api;
mod runtime;

use anyhow::{Context, Result};
use clap::Parser;
use ferxium_core::{Discovery, storage};
use rand::RngCore;
use std::{
    fs::OpenOptions,
    sync::{Arc, atomic::Ordering},
};

#[derive(Parser)]
#[command(
    version,
    about = "FerXium local protection service; run as your normal user"
)]
struct Args {
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// Override private state location for isolated development/tests.
    #[arg(long)]
    data_dir: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ferxium_service=info".into()),
        )
        .init();
    let args = Args::parse();
    ferxium_core::privilege::require_regular_user()?;
    let data = args.data_dir.map(Ok).unwrap_or_else(storage::data_dir)?;
    storage::private_dir(&data)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(data.join("service.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("Another FerXium service is already running")?;
    let app = Arc::new(runtime::App::load(data.clone())?);
    let listener =
        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, args.port)).await?;
    let mut token = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let token = hex::encode(token);
    storage::write_json(
        &data.join("service.json"),
        &Discovery {
            port: listener.local_addr()?.port(),
            token: token.clone(),
            pid: std::process::id(),
        },
    )?;
    app.event(
        "info",
        "Service started. Scans and activity remain on this device.",
    );
    let (tx, rx) = tokio::sync::mpsc::channel(4096);
    runtime::spawn_background(app.clone(), tx, rx);
    tracing::info!("Local protection service ready (no remote access, no telemetry)");
    let router = api::router(app.clone(), token);
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    app.shutdown.store(true, Ordering::Release);
    app.cancel_active();
    // Wait for a cooperative scan to settle before persisting final state.
    for _ in 0..100 {
        if !app.scan_active() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    app.persist()?;
    let _ = std::fs::remove_file(data.join("service.json"));
    result?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = signal.recv() => {} }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
