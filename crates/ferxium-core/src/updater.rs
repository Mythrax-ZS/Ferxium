//! The pinned key authenticates exact UTF-8 payload bytes, never reserialized JSON.
use crate::{Config, scanner::SignatureDatabase, storage};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub payload: String,
    pub signature: String,
}

pub fn verify(
    envelope: &SignedEnvelope,
    key_hex: &str,
    current_version: u64,
) -> Result<SignatureDatabase> {
    let key: [u8; 32] = hex::decode(key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid update public key"))?;
    let signature = Signature::from_slice(&hex::decode(&envelope.signature)?)?;
    VerifyingKey::from_bytes(&key)?.verify_strict(envelope.payload.as_bytes(), &signature)?;
    let database = SignatureDatabase::parse(envelope.payload.as_bytes())?;
    ensure!(
        database.version > current_version,
        "Update is not newer; rollback or replay refused"
    );
    ensure!(
        database.published_at <= Utc::now() + chrono::Duration::minutes(10),
        "Database publication is in the future"
    );
    Ok(database)
}

pub async fn fetch(
    config: &Config,
    current_version: u64,
) -> Result<(SignedEnvelope, SignatureDatabase)> {
    config.validate()?;
    let url = config
        .update_manifest_url
        .as_deref()
        .context("No signature feed configured")?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .build()?;
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len() + chunk.len() <= 5 * 1024 * 1024,
            "Update response exceeds limit"
        );
        body.extend_from_slice(&chunk);
    }
    let envelope: SignedEnvelope = serde_json::from_slice(&body)?;
    let database = verify(
        &envelope,
        config
            .update_public_key
            .as_deref()
            .context("Missing trusted key")?,
        current_version,
    )?;
    Ok((envelope, database))
}

pub fn install(path: &Path, envelope: &SignedEnvelope) -> Result<()> {
    storage::write_json(path, envelope)
}
