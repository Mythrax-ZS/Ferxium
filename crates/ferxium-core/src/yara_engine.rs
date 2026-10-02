use crate::{Finding, Severity};
use anyhow::Result;

pub struct YaraEngine {
    #[cfg(feature = "yara-engine")]
    rules: yara::Rules,
}

impl YaraEngine {
    pub fn new(source: &str) -> Result<Self> {
        #[cfg(feature = "yara-engine")]
        {
            let compiler = yara::Compiler::new()?.add_rules_str(source)?;
            Ok(Self {
                rules: compiler.compile_rules()?,
            })
        }
        #[cfg(not(feature = "yara-engine"))]
        {
            let _ = source;
            Ok(Self {})
        }
    }

    pub fn enabled(&self) -> bool {
        cfg!(feature = "yara-engine")
    }

    pub fn scan(&self, bytes: &[u8]) -> Result<Vec<Finding>> {
        #[cfg(feature = "yara-engine")]
        {
            Ok(self
                .rules
                .scan_mem(bytes, 3)?
                .into_iter()
                .map(|rule| {
                    let text_meta = |key| {
                        rule.metadatas.iter().find_map(|meta| {
                            if meta.identifier == key
                                && let yara::MetadataValue::String(value) = &meta.value
                            {
                                return Some(*value);
                            }
                            None
                        })
                    };
                    Finding {
                        name: rule.identifier.to_owned(),
                        method: "yara".into(),
                        severity: match text_meta("severity") {
                            Some("low") => Severity::Low,
                            Some("high") => Severity::High,
                            Some("critical") => Severity::Critical,
                            _ => Severity::Medium,
                        },
                        explanation: text_meta("description")
                            .filter(|value| value.len() <= 2000)
                            .unwrap_or("YARA rule matched; review context before taking action.")
                            .to_owned(),
                    }
                })
                .collect())
        }
        #[cfg(not(feature = "yara-engine"))]
        {
            let _ = (bytes, Severity::Low);
            Ok(vec![])
        }
    }
}
