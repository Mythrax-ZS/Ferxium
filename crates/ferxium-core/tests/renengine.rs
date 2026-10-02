//! Inert indicator fixtures only: no malware, network requests, or executable scripts.
use chrono::Utc;
use ferxium_core::{
    scanner::{Md5Signature, SignatureDatabase},
    *,
};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::fs;
use tempfile::tempdir;

#[test]
fn legacy_md5_lookup_retains_sha256_identity_and_allowlist() {
    let bytes = b"abc"; // Published MD5 test vector, not a malware sample.
    assert_eq!(
        hex::encode(Md5::digest(bytes)),
        "900150983cd24fb0d6963f7d28e17f72"
    );
    let engine = Scanner::new(
        SignatureDatabase {
            version: 1,
            published_at: Utc::now(),
            signatures: vec![],
            md5_signatures: vec![Md5Signature {
                md5: "900150983cd24fb0d6963f7d28e17f72".into(),
                name: "Harmless.MD5Fixture".into(),
                severity: Severity::Low,
                description: "Inert legacy IOC lookup test".into(),
            }],
        },
        BUNDLED_RULES,
    )
    .unwrap();
    let dir = tempdir().unwrap();
    let path = dir.path().join("inert.txt");
    fs::write(&path, bytes).unwrap();
    let FileOutcome::Detected { threat } = engine.scan_file(&path, &Config::default()).unwrap()
    else {
        panic!("Expected the harmless MD5 fixture");
    };
    assert_eq!(threat.sha256, hex::encode(Sha256::digest(bytes)));
    assert_eq!(threat.findings[0].method, "md5_ioc");
    let allowed = Config {
        allowed_hashes: vec![threat.sha256],
        ..Config::default()
    };
    assert!(matches!(
        engine.scan_file(&path, &allowed).unwrap(),
        FileOutcome::Skipped { .. }
    ));
    fs::write(&path, b"abcd").unwrap();
    assert!(matches!(
        engine.scan_file(&path, &Config::default()).unwrap(),
        FileOutcome::Clean { .. }
    ));
}

#[test]
fn published_iocs_are_valid_and_invalid_report_hash_is_not_guessed() {
    let database = SignatureDatabase::parse(BUNDLED_DATABASE.as_bytes()).unwrap();
    assert_eq!(
        database
            .md5_signatures
            .iter()
            .map(|s| s.md5.as_str())
            .collect::<Vec<_>>(),
        [
            "29203ca123d51b1b33505a0813d360df",
            "810f257542018be0fc62af542d13d012",
            "681db529e402467a4b0567c82a350fc0",
            "2e116632248a7e1f8aa6bca92d9c1c90",
        ]
    );
    let mut value = serde_json::to_value(database).unwrap();
    let original = value["md5_signatures"][0].clone();
    for invalid in [
        "F8453EFE408CE25B9484F872797E3D63",
        "29203CA123D51B1B33505A0813D360DF",
        "z9203ca123d51b1b33505a0813d360df",
        "",
    ] {
        value["md5_signatures"][0]["md5"] = invalid.into();
        assert!(SignatureDatabase::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    value["md5_signatures"][0] = original.clone();
    value["md5_signatures"]
        .as_array_mut()
        .unwrap()
        .push(original);
    assert!(SignatureDatabase::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    value.as_object_mut().unwrap().remove("md5_signatures");
    assert!(
        SignatureDatabase::parse(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .md5_signatures
            .is_empty()
    );
}

#[cfg(feature = "yara-engine")]
mod patterns {
    use super::*;

    // A fake DOS/PE header plus words is deliberately not a runnable program.
    fn fixture(tokens: &[&str], pe: bool, wide: bool) -> Vec<u8> {
        let mut bytes = if pe {
            let mut header = vec![0u8; 144];
            header[..2].copy_from_slice(b"MZ");
            header[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
            header[128..132].copy_from_slice(b"PE\0\0");
            header
        } else {
            vec![]
        };
        let text = format!("Harmless static indicator fixture\n{}", tokens.join("\n"));
        if wide {
            bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        } else {
            bytes.extend(text.as_bytes());
        }
        bytes
    }

    #[test]
    fn each_campaign_pattern_requires_every_distinctive_signal() {
        let cases: &[(&str, &[&str], bool)] = &[
            (
                "FerXium_RenEngine_Config_Loader",
                &[
                    "81034149cd6f48c8821340204f92766e",
                    "A50YyY1",
                    ".GEg",
                    "is_sandboxed",
                ],
                false,
            ),
            (
                "FerXium_RenEngine_MSBuild_Launcher",
                &[
                    "MSBUILDENABLEALLPROPERTYFUNCTIONS=1",
                    "_czzf",
                    "Nancy.csproj",
                    "MSBuild.exe",
                    "conhost.exe",
                    "--headless",
                ],
                false,
            ),
            (
                "FerXium_RenEngine_MSBuild_Reflective_Load",
                &[
                    "<Project",
                    "DefaultEvaluator5",
                    "AppDomain",
                    "CurrentDomain",
                    ".Load(",
                    "CreateInstance",
                ],
                false,
            ),
            (
                "FerXium_RenEngine_Trojanized_Nancy",
                &[
                    "DefaultEvaluator5",
                    "Nancy.Runtime.mvlorimu",
                    "Nancy.Data.tcnlhxw",
                    "Nancy.Resources.kxxodp",
                ],
                true,
            ),
            (
                "FerXium_RenEngine_EtherHiding_Downloader",
                &[
                    "0x328a1fadff154290f0ce1389a4e633698cdfdaa7",
                    "0x06fdde03",
                    "eth_call",
                    "GollopDevest",
                ],
                true,
            ),
        ];
        let engine = Scanner::bundled().unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("inert-fixture.txt");
        for &(name, tokens, pe) in cases {
            for wide in [false, true] {
                fs::write(&path, fixture(tokens, pe, wide)).unwrap();
                let FileOutcome::Detected { threat } =
                    engine.scan_file(&path, &Config::default()).unwrap()
                else {
                    panic!("Missed {name} (wide={wide})");
                };
                let finding = threat.findings.iter().find(|f| f.name == name).unwrap();
                assert_eq!(finding.severity, Severity::High);
                assert_eq!(finding.method, "yara");
                assert!(!finding.explanation.starts_with("YARA rule matched"));
                for missing in 0..tokens.len() {
                    let remaining = tokens
                        .iter()
                        .enumerate()
                        .filter_map(|(i, &s)| (i != missing).then_some(s))
                        .collect::<Vec<_>>();
                    fs::write(&path, fixture(&remaining, pe, wide)).unwrap();
                    assert!(
                        matches!(
                            engine.scan_file(&path, &Config::default()).unwrap(),
                            FileOutcome::Clean { .. }
                        ),
                        "False positive {name}, missing {}",
                        tokens[missing]
                    );
                }
                if pe {
                    fs::write(&path, fixture(tokens, false, wide)).unwrap();
                    assert!(
                        matches!(
                            engine.scan_file(&path, &Config::default()).unwrap(),
                            FileOutcome::Clean { .. }
                        ),
                        "Documentation text must not match PE rule {name}"
                    );
                }
            }
        }
    }

    #[test]
    fn normal_game_build_library_and_blockchain_indicators_are_clean() {
        let engine = Scanner::bundled().unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("inert.txt");
        for tokens in [
            vec![
                "Ren'Py",
                "renpy",
                "libwin32.rpa",
                "sys_config",
                "is_sandboxed",
            ],
            vec![
                "MSBuild.exe",
                "MSBUILDENABLEALLPROPERTYFUNCTIONS=1",
                "Nancy.csproj",
                "conhost.exe",
            ],
            vec![
                "Nancy",
                "DefaultEvaluator",
                "AppDomain",
                "CurrentDomain",
                "CreateInstance",
            ],
            vec!["eth_call", "bsc-dataseed.binance.org", "0x06fdde03"],
            vec![
                "0x328a1fadff154290f0ce1389a4e633698cdfdaa7",
                "eth_call",
                "0x06fdde03",
            ],
        ] {
            fs::write(&path, fixture(&tokens, true, false)).unwrap();
            assert!(matches!(
                engine.scan_file(&path, &Config::default()).unwrap(),
                FileOutcome::Clean { .. }
            ));
        }
    }

    #[test]
    fn embedded_rule_source_does_not_match_campaign_or_marker_rules() {
        let engine = Scanner::bundled().unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("fake-embedded-rules.bin");
        // Keep the fake executable above the generic script rule's size limit.
        let mut bytes = fixture(&[BUNDLED_RULES], true, false);
        bytes.resize(1024 * 1024 + 1, 0);
        fs::write(&path, bytes).unwrap();
        let outcome = engine.scan_file(&path, &Config::default()).unwrap();
        assert!(
            matches!(outcome, FileOutcome::Clean { .. }),
            "Embedded rule source matched: {outcome:?}"
        );
    }
}
