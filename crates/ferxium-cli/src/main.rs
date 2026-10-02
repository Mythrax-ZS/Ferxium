use anyhow::Result;
use clap::{Parser, Subcommand};
use ferxium_core::{Config, Discovery, FileOutcome, Scanner, storage};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "FerXium local scanner and service diagnostics")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Scan without the daemon. Exit: 0 no detections, 1 detections, 2 scan errors.
    Scan { path: PathBuf },
    /// Read live status via authenticated loopback IPC.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Scan { path } => {
            let engine = Scanner::bundled()?;
            let config = Config::default();
            let mut threats = 0;
            let mut errors = 0;
            for entry in walkdir::WalkDir::new(path).follow_links(false).max_open(32) {
                match entry {
                    Ok(entry) if entry.file_type().is_file() => {
                        match engine.scan_file(entry.path(), &config) {
                            Ok(outcome) => {
                                if matches!(outcome, FileOutcome::Detected { .. }) {
                                    threats += 1;
                                }
                                println!(
                                    "{}",
                                    serde_json::to_string(
                                        &serde_json::json!({"path":entry.path(),"result":outcome})
                                    )?
                                );
                            }
                            Err(error) => {
                                errors += 1;
                                eprintln!("{}: {error}", entry.path().display());
                            }
                        }
                    }
                    Err(error) => {
                        errors += 1;
                        eprintln!("{error}");
                    }
                    _ => {}
                }
            }
            std::process::exit(if errors > 0 {
                2
            } else if threats > 0 {
                1
            } else {
                0
            });
        }
        Command::Status => {
            let discovery: Discovery =
                storage::read_json(&storage::data_dir()?.join("service.json"))?;
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?;
            let status = client
                .get(format!("http://127.0.0.1:{}/v1/status", discovery.port))
                .bearer_auth(discovery.token)
                .send()
                .await?
                .error_for_status()?
                .json::<serde_json::Value>()
                .await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
    }
    Ok(())
}
