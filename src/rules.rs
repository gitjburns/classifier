use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use regex::{Regex, RegexSet};
use serde::Deserialize;

use crate::types::Severity;

/// Names the built-in analyzer that detects Unicode tag-block characters.
pub const UNICODE_TAGS_ID: &str = "unicode-tags";
/// Names the built-in analyzer that detects suspicious zero-width characters.
pub const ZERO_WIDTH_ID: &str = "zero-width";
/// Names the built-in analyzer that detects directional formatting controls.
pub const BIDI_OVERRIDE_ID: &str = "bidi-override";
/// Names the built-in analyzer that detects look-alike script mixing within words.
pub const MIXED_SCRIPT_ID: &str = "mixed-script";
/// Names the built-in analyzer that detects opaque encoded segments.
pub const ENCODED_BLOB_ID: &str = "encoded-blob";
/// Names the advisory analyzer that detects unusually high non-ASCII density.
pub const HIGH_NONASCII_ID: &str = "high-nonascii";

const ANALYZER_IDS: [&str; 6] = [
    UNICODE_TAGS_ID,
    ZERO_WIDTH_ID,
    BIDI_OVERRIDE_ID,
    MIXED_SCRIPT_ID,
    ENCODED_BLOB_ID,
    HIGH_NONASCII_ID,
];

/// Holds common settings for analyzers that require no tuning parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerConfig {
    /// Makes disabling a known analyzer explicit rather than relying on omission.
    pub enabled: bool,
    /// Determines how findings from this analyzer affect verdict selection.
    pub severity: Severity,
}

/// Holds the bounds used to identify high-entropy base64 or hexadecimal runs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncodedBlobConfig {
    /// Makes disabling this analyzer explicit while retaining its required tuning.
    pub enabled: bool,
    /// Determines how encoded-segment findings affect verdict selection.
    pub severity: Severity,
    /// Prevents short ordinary words from entering entropy analysis.
    pub min_run_length: usize,
    /// Requires enough per-character entropy to distinguish opaque data from repetition.
    pub min_entropy: f64,
}

/// Holds the document-size and ratio bounds for the non-ASCII advisory signal.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighNonasciiConfig {
    /// Makes disabling this analyzer explicit while retaining its required tuning.
    pub enabled: bool,
    /// Preserves the configured advisory classification in each finding.
    pub severity: Severity,
    /// Sets the non-ASCII proportion above which the advisory signal is emitted.
    pub max_ratio: f64,
    /// Avoids classifying short multilingual snippets by a document-level ratio.
    pub min_total_chars: usize,
}

/// Collects the validated settings for every analyzer implemented by the binary.
#[derive(Debug)]
pub struct AnalyzerSettings {
    /// Configures detection of Unicode tag-block characters.
    pub unicode_tags: AnalyzerConfig,
    /// Configures detection of suspicious zero-width characters.
    pub zero_width: AnalyzerConfig,
    /// Configures detection of directional formatting controls.
    pub bidi_override: AnalyzerConfig,
    /// Configures detection of look-alike script mixing within words.
    pub mixed_script: AnalyzerConfig,
    /// Configures detection of opaque encoded segments.
    pub encoded_blob: EncodedBlobConfig,
    /// Configures the document-level non-ASCII advisory signal.
    pub high_nonascii: HighNonasciiConfig,
}

impl AnalyzerSettings {
    /// Reports how many analyzers startup will make active for operator diagnostics.
    pub fn enabled_count(&self) -> usize {
        [
            self.unicode_tags.enabled,
            self.zero_width.enabled,
            self.bidi_override.enabled,
            self.mixed_script.enabled,
            self.encoded_blob.enabled,
            self.high_nonascii.enabled,
        ]
        .into_iter()
        .filter(|enabled| *enabled)
        .count()
    }
}

/// Retains the rule metadata alongside the finite-automaton matcher compiled at startup.
#[derive(Debug)]
pub struct CompiledPattern {
    /// Uniquely names the finding producer within the shared rule-id namespace.
    pub id: String,
    /// Determines how matches participate in verdict selection.
    pub severity: Severity,
    /// Guarantees linear-time matching over normalized untrusted content.
    pub regex: Regex,
}

/// Contains the atomic, fully validated rule inventory handed to the assessment pipeline.
#[derive(Debug)]
pub struct CompiledRuleset {
    /// Identifies the exact inventory that produced an assessment.
    pub version: String,
    /// Contains every compiled data-driven pattern in file order.
    pub patterns: Vec<CompiledPattern>,
    /// Rejects normalized content that cannot match any pattern before exact span scans.
    pub pattern_prefilter: RegexSet,
    /// Contains explicit settings for every analyzer known to the binary.
    pub analyzers: AnalyzerSettings,
}

/// Preserves the file, available pattern identity, and source failure for startup diagnostics.
#[derive(Debug)]
pub enum RulesError {
    /// Retains the OS failure encountered while reading the configured rules path.
    ReadRules { path: PathBuf, source: io::Error },
    /// Retains TOML location and schema context for strict parsing failures.
    ParseRules {
        path: PathBuf,
        source: toml::de::Error,
    },
    /// Identifies a known analyzer whose explicit section was omitted.
    MissingAnalyzer {
        path: PathBuf,
        analyzer_id: &'static str,
    },
    /// Identifies an analyzer tuning value outside its finite semantic domain.
    InvalidAnalyzerSetting {
        path: PathBuf,
        analyzer_id: &'static str,
        setting: &'static str,
        value: f64,
        required_range: &'static str,
    },
    /// Identifies two pattern entries competing for the same finding id.
    DuplicatePatternId { path: PathBuf, rule_id: String },
    /// Prevents a pattern from impersonating a built-in analyzer in audit records.
    AnalyzerIdCollision { path: PathBuf, rule_id: String },
    /// Retains the regex compiler's exact rejection and owning pattern id.
    CompileRegex {
        path: PathBuf,
        rule_id: String,
        source: regex::Error,
    },
    /// Preserves the aggregate compiler failure after every individual pattern is valid.
    CompileRegexSet { path: PathBuf, source: regex::Error },
}

impl CompiledRuleset {
    /// Loads, strictly validates, and compiles the configured inventory as one atomic unit.
    pub fn load(path: &Path) -> Result<Self, RulesError> {
        let contents = fs::read_to_string(path).map_err(|source| RulesError::ReadRules {
            path: path.to_path_buf(),
            source,
        })?;
        let rules_file =
            toml::from_str::<RulesFile>(&contents).map_err(|source| RulesError::ParseRules {
                path: path.to_path_buf(),
                source,
            })?;

        rules_file.compile(path)
    }
}

impl fmt::Display for RulesError {
    /// Formats each fatal failure with the configured path and closest known rule identity.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadRules { path, source } => {
                write!(
                    formatter,
                    "failed to read rules file {}: {source}",
                    path.display()
                )
            }
            Self::ParseRules { path, source } => {
                write!(
                    formatter,
                    "failed to parse rules file {}: {source}",
                    path.display()
                )
            }
            Self::MissingAnalyzer { path, analyzer_id } => write!(
                formatter,
                "rules file {} is missing required analyzer section {analyzer_id:?}",
                path.display()
            ),
            Self::InvalidAnalyzerSetting {
                path,
                analyzer_id,
                setting,
                value,
                required_range,
            } => write!(
                formatter,
                "rules file {} analyzer {analyzer_id:?} setting {setting:?} must be {required_range}, got {value:?}",
                path.display()
            ),
            Self::DuplicatePatternId { path, rule_id } => write!(
                formatter,
                "rules file {} contains duplicate pattern id {rule_id:?}",
                path.display()
            ),
            Self::AnalyzerIdCollision { path, rule_id } => write!(
                formatter,
                "rules file {} pattern id {rule_id:?} collides with a built-in analyzer id",
                path.display()
            ),
            Self::CompileRegex {
                path,
                rule_id,
                source,
            } => write!(
                formatter,
                "failed to compile pattern {rule_id:?} from rules file {}: {source}",
                path.display()
            ),
            Self::CompileRegexSet { path, source } => write!(
                formatter,
                "failed to compile pattern prefilter from rules file {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for RulesError {
    /// Exposes concrete I/O, TOML, and regex failures without erasing source context.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReadRules { source, .. } => Some(source),
            Self::ParseRules { source, .. } => Some(source),
            Self::CompileRegex { source, .. } | Self::CompileRegexSet { source, .. } => {
                Some(source)
            }
            Self::MissingAnalyzer { .. }
            | Self::InvalidAnalyzerSetting { .. }
            | Self::DuplicatePatternId { .. }
            | Self::AnalyzerIdCollision { .. } => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    version: String,
    analyzer: AnalyzerSections,
    pattern: Vec<PatternConfig>,
}

impl RulesFile {
    /// Converts the parsed file only after all required sections and shared ids are valid.
    fn compile(self, path: &Path) -> Result<CompiledRuleset, RulesError> {
        let analyzers = self.analyzer.require_all(path)?;
        // A density ratio is meaningful only on the closed unit interval. Enforcing that domain at
        // load time also makes the ASCII analyzer fast path behavior-equivalent for every ruleset.
        let max_ratio = analyzers.high_nonascii.max_ratio;
        if !max_ratio.is_finite() || !(0.0..=1.0).contains(&max_ratio) {
            return Err(RulesError::InvalidAnalyzerSetting {
                path: path.to_path_buf(),
                analyzer_id: HIGH_NONASCII_ID,
                setting: "max_ratio",
                value: max_ratio,
                required_range: "a finite number within 0.0..=1.0",
            });
        }
        let mut pattern_ids = HashSet::with_capacity(self.pattern.len());
        let mut patterns = Vec::with_capacity(self.pattern.len());
        let mut pattern_sources = Vec::with_capacity(self.pattern.len());

        for pattern in self.pattern {
            if ANALYZER_IDS.contains(&pattern.id.as_str()) {
                return Err(RulesError::AnalyzerIdCollision {
                    path: path.to_path_buf(),
                    rule_id: pattern.id,
                });
            }
            if !pattern_ids.insert(pattern.id.clone()) {
                return Err(RulesError::DuplicatePatternId {
                    path: path.to_path_buf(),
                    rule_id: pattern.id,
                });
            }

            // Description is required author-facing metadata, not executable matching state.
            drop(pattern.description);
            let regex = Regex::new(&pattern.regex).map_err(|source| RulesError::CompileRegex {
                path: path.to_path_buf(),
                rule_id: pattern.id.clone(),
                source,
            })?;
            patterns.push(CompiledPattern {
                id: pattern.id,
                severity: pattern.severity,
                regex,
            });
            pattern_sources.push(pattern.regex);
        }

        // Aggregate compilation follows every per-pattern check so existing validation order and
        // rule-specific regex diagnostics remain authoritative.
        let pattern_prefilter =
            RegexSet::new(&pattern_sources).map_err(|source| RulesError::CompileRegexSet {
                path: path.to_path_buf(),
                source,
            })?;

        Ok(CompiledRuleset {
            version: self.version,
            patterns,
            pattern_prefilter,
            analyzers,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyzerSections {
    #[serde(rename = "unicode-tags")]
    unicode_tags: Option<AnalyzerConfig>,
    #[serde(rename = "zero-width")]
    zero_width: Option<AnalyzerConfig>,
    #[serde(rename = "bidi-override")]
    bidi_override: Option<AnalyzerConfig>,
    #[serde(rename = "mixed-script")]
    mixed_script: Option<AnalyzerConfig>,
    #[serde(rename = "encoded-blob")]
    encoded_blob: Option<EncodedBlobConfig>,
    #[serde(rename = "high-nonascii")]
    high_nonascii: Option<HighNonasciiConfig>,
}

impl AnalyzerSections {
    /// Rejects omission so disabled analyzers remain deliberate, reviewable configuration.
    fn require_all(self, path: &Path) -> Result<AnalyzerSettings, RulesError> {
        Ok(AnalyzerSettings {
            unicode_tags: require_analyzer(self.unicode_tags, path, UNICODE_TAGS_ID)?,
            zero_width: require_analyzer(self.zero_width, path, ZERO_WIDTH_ID)?,
            bidi_override: require_analyzer(self.bidi_override, path, BIDI_OVERRIDE_ID)?,
            mixed_script: require_analyzer(self.mixed_script, path, MIXED_SCRIPT_ID)?,
            encoded_blob: require_analyzer(self.encoded_blob, path, ENCODED_BLOB_ID)?,
            high_nonascii: require_analyzer(self.high_nonascii, path, HIGH_NONASCII_ID)?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternConfig {
    id: String,
    severity: Severity,
    description: String,
    regex: String,
}

/// Converts an optional parse field into the required explicit analyzer setting.
fn require_analyzer<T>(
    analyzer: Option<T>,
    path: &Path,
    analyzer_id: &'static str,
) -> Result<T, RulesError> {
    analyzer.ok_or_else(|| RulesError::MissingAnalyzer {
        path: path.to_path_buf(),
        analyzer_id,
    })
}
