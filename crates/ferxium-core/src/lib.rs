//! A local-first engine. Files are untrusted input; no sample is ever executed.
pub mod config;
pub mod models;
pub mod privilege;
pub mod quarantine;
pub mod realtime;
pub mod scanner;
pub mod storage;
pub mod updater;
pub mod yara_engine;

pub use config::Config;
pub use models::*;
pub use scanner::Scanner;

pub const BUNDLED_DATABASE: &str = include_str!("../../../signatures/hashes.json");
pub const BUNDLED_RULES: &str = concat!(
    include_str!("../../../signatures/examples.yar"),
    "\n",
    include_str!("../../../signatures/renengine-2026-07.yar")
);
