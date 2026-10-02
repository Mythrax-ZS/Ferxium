use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use ferxium_core::{
    quarantine::Quarantine,
    scanner::{HashSignature, SignatureDatabase},
    storage,
    updater::{self, SignedEnvelope},
    *,
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use tempfile::tempdir;
use uuid::Uuid;

const SAMPLE: &[u8] = b"Harmless deterministic FerXium security test fixture.";
fn scanner() -> Scanner {
    Scanner::new(
        SignatureDatabase {
            version: 1,
            published_at: Utc::now(),
            md5_signatures: vec![],
            signatures: vec![HashSignature {
                sha256: hex::encode(Sha256::digest(SAMPLE)),
                name: "Harmless.HashFixture".into(),
                severity: Severity::Low,
                description: "Not malware".into(),
            }],
        },
        BUNDLED_RULES,
    )
    .unwrap()
}
fn detect(path: &Path) -> Threat {
    match scanner().scan_file(path, &Config::default()).unwrap() {
        FileOutcome::Detected { threat } => threat,
        _ => panic!("Expected hash fixture detection"),
    }
}

#[test]
fn hash_detection_whitelist_and_size_limit_are_distinct() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("fixture.txt");
    fs::write(&path, SAMPLE).unwrap();
    let engine = scanner();
    let threat = detect(&path);
    assert_eq!(threat.findings[0].method, "sha256");
    let mut config = Config::default();
    config.allowed_hashes.push(threat.sha256);
    assert!(matches!(
        engine.scan_file(&path, &config).unwrap(),
        FileOutcome::Skipped { .. }
    ));
    config.allowed_hashes.clear();
    config.max_file_bytes = 2;
    assert!(matches!(
        engine.scan_file(&path, &config).unwrap(),
        FileOutcome::Skipped { .. }
    ));
    fs::write(&path, b"Different benign content").unwrap();
    assert!(matches!(
        engine.scan_file(&path, &Config::default()).unwrap(),
        FileOutcome::Clean { .. }
    ));
}

#[test]
fn exclusions_use_path_components_not_string_prefixes() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("excluded");
    let b = dir.path().join("excluded-other");
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    let mut config = Config::default();
    config.exclusions.push(a.clone());
    assert!(config.excludes(&a.join("child")));
    assert!(!config.excludes(&b));
}

#[test]
fn quarantine_encrypts_authenticates_and_never_overwrites() {
    let dir = tempdir().unwrap();
    let state = dir.path().join("state");
    storage::private_dir(&state).unwrap();
    let file = dir.path().join("sample.txt");
    fs::write(&file, SAMPLE).unwrap();
    let threat = detect(&file);
    let vault = Quarantine::open(&state).unwrap();
    let record = vault.contain(&threat, 1024).unwrap();
    assert!(record.source_removed);
    assert!(!file.exists());
    assert_eq!(vault.list().unwrap().len(), 1);
    let blob_path = state.join("quarantine").join(format!("{}.agq", record.id));
    let original_blob = fs::read(&blob_path).unwrap();
    assert!(!original_blob.windows(SAMPLE.len()).any(|w| w == SAMPLE));
    let destination = dir.path().join("restored.txt");
    fs::write(&destination, b"must survive").unwrap();
    assert!(vault.restore(record.id, &destination).is_err());
    assert_eq!(fs::read(&destination).unwrap(), b"must survive");
    let restored = dir.path().join("fresh.txt");
    assert!(
        vault
            .restore(record.id, &state.join("unexpected-restore.txt"))
            .is_err()
    );
    #[cfg(windows)]
    {
        assert!(vault.restore(record.id, &dir.path().join("NUL")).is_err());
        assert!(
            vault
                .restore(record.id, &dir.path().join("file.txt:stream"))
                .is_err()
        );
    }
    vault.restore(record.id, &restored).unwrap();
    assert_eq!(fs::read(restored).unwrap(), SAMPLE);
    let mut corrupt = original_blob;
    corrupt[15] ^= 1;
    fs::write(&blob_path, corrupt).unwrap();
    let tampered = dir.path().join("tampered.txt");
    assert!(vault.restore(record.id, &tampered).is_err());
    assert!(!tampered.exists());
    assert!(vault.delete(Uuid::new_v4()).is_err());
    vault.delete(record.id).unwrap();
    assert!(vault.list().unwrap().is_empty());
}

#[test]
fn changed_source_cannot_be_quarantined_using_an_old_report() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("sample.txt");
    fs::write(&file, SAMPLE).unwrap();
    let threat = detect(&file);
    fs::write(&file, b"replacement is legitimate").unwrap();
    let state = dir.path().join("state");
    storage::private_dir(&state).unwrap();
    assert!(
        Quarantine::open(&state)
            .unwrap()
            .contain(&threat, 1024)
            .is_err()
    );
    assert_eq!(fs::read(file).unwrap(), b"replacement is legitimate");
}

#[test]
fn signatures_reject_forgery_replay_and_payload_mutation() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let mut database: serde_json::Value = serde_json::from_str(BUNDLED_DATABASE).unwrap();
    database["version"] = 3.into();
    let payload = serde_json::to_string(&database).unwrap();
    let signature = hex::encode(key.sign(payload.as_bytes()).to_bytes());
    let signed = SignedEnvelope { payload, signature };
    assert_eq!(updater::verify(&signed, &pubkey, 2).unwrap().version, 3);
    assert!(updater::verify(&signed, &pubkey, 3).is_err());
    let wrong = SigningKey::from_bytes(&[8u8; 32]);
    assert!(updater::verify(&signed, &hex::encode(wrong.verifying_key().to_bytes()), 1).is_err());
    let modified = SignedEnvelope {
        payload: signed.payload + " ",
        signature: signed.signature,
    };
    assert!(updater::verify(&modified, &pubkey, 1).is_err());
}

#[test]
fn configuration_rejects_implicit_cloud_and_invalid_limits() {
    let mut config = Config {
        cloud_lookup_enabled: true,
        ..Config::default()
    };
    assert!(config.validate().is_err());
    config.cloud_lookup_enabled = false;
    config.scan_interval_hours = Some(0);
    assert!(config.validate().is_err());
    config.scan_interval_hours = None;
    config.allowed_hashes.push("not-a-sha256".into());
    assert!(config.validate().is_err());
}

#[test]
fn missing_quarantine_key_does_not_silently_replace_a_backup_key() {
    let dir = tempdir().unwrap();
    let state = dir.path().join("state");
    storage::private_dir(&state).unwrap();
    let file = dir.path().join("fixture.txt");
    fs::write(&file, SAMPLE).unwrap();
    let threat = detect(&file);
    let vault = Quarantine::open(&state).unwrap();
    vault.contain(&threat, 1024).unwrap();
    drop(vault);
    let key = state.join("quarantine/key.bin");
    fs::remove_file(&key).unwrap();
    assert!(Quarantine::open(&state).is_err());
    assert!(!key.exists());
}

#[test]
fn script_heuristics_require_multiple_signals_and_can_be_disabled() {
    let dir = tempdir().unwrap();
    let script = dir.path().join("review-fixture.ps1");
    fs::write(
        &script,
        b"# harmless test: Invoke-WebRequest\n# Invoke-Expression\n# -executionpolicy bypass",
    )
    .unwrap();
    let config = Config::default();
    assert!(
        matches!(scanner().scan_file(&script, &config).unwrap(), FileOutcome::Detected { threat } if threat.findings.iter().any(|f|f.method=="heuristic"))
    );
    let config = Config {
        heuristics_enabled: false,
        ..config
    };
    assert!(matches!(
        scanner().scan_file(&script, &config).unwrap(),
        FileOutcome::Clean { .. }
    ));
    fs::write(&script, b"# Ordinary Invoke-WebRequest documentation").unwrap();
    assert!(matches!(
        scanner().scan_file(&script, &Config::default()).unwrap(),
        FileOutcome::Clean { .. }
    ));
}

#[cfg(unix)]
#[test]
fn symlinks_and_special_files_are_not_scanned() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("sample");
    fs::write(&file, SAMPLE).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(scanner().scan_file(&link, &Config::default()).is_err());
    assert!(storage::open_regular(Path::new("/dev/null")).is_err());
}

#[cfg(feature = "yara-engine")]
#[test]
fn yara_marker_detects_a_harmless_fixture() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("marker.txt");
    fs::write(&file, b"FERXIUM_TEST_SIGNATURE_v1").unwrap();
    let result = Scanner::bundled()
        .unwrap()
        .scan_file(&file, &Config::default())
        .unwrap();
    assert!(
        matches!(result, FileOutcome::Detected { threat } if threat.findings.iter().any(|f|f.method=="yara"))
    );
}
