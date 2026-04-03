//! Pipeline for batch file scanning with rayon parallelism.

use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::allowlist::Allowlist;
use crate::models::Match;
use crate::scanner::{self, ScanConfig};

/// Default maximum file size (100 MB).
pub const DEFAULT_MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

/// A file to be processed by the pipeline.
#[derive(Debug, Clone)]
pub struct FileJob {
    /// Path to the file.
    pub file_path: PathBuf,
    /// Categories to scan.
    pub categories: Option<HashSet<String>>,
    /// Only report matches with context.
    pub require_context: bool,
    /// Maximum matches for this file.
    pub max_matches: usize,
}

impl FileJob {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            file_path: path.into(),
            categories: None,
            require_context: false,
            max_matches: 50_000,
        }
    }
}

/// Result from processing a single file.
#[derive(Debug, Clone, Serialize)]
pub struct PipelineResult {
    pub file_path: String,
    pub matches: Vec<Match>,
    pub format_detected: String,
    pub duration_ms: f64,
    pub error: Option<String>,
    pub file_size_bytes: u64,
    pub extracted_text_length: usize,
}

impl PipelineResult {
    pub fn success(&self) -> bool {
        self.error.is_none()
    }

    pub fn match_count(&self) -> usize {
        self.matches.len()
    }
}

/// Parallel file scanning pipeline.
pub struct Pipeline {
    /// Maximum file size to process.
    max_file_size: usize,
    /// Categories to scan.
    categories: Option<HashSet<String>>,
    /// Require context keywords.
    require_context: bool,
    /// Minimum confidence threshold.
    min_confidence: f64,
    /// Whether to deduplicate matches.
    deduplicate: bool,
    /// Allowlist for suppression.
    allowlist: Option<Allowlist>,
}

impl Pipeline {
    /// Create a new pipeline with default settings.
    pub fn new() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            categories: None,
            require_context: false,
            min_confidence: 0.0,
            deduplicate: true,
            allowlist: None,
        }
    }

    /// Set maximum file size.
    pub fn with_max_file_size(mut self, size: usize) -> Self {
        self.max_file_size = size;
        self
    }

    /// Set categories to scan.
    pub fn with_categories(mut self, categories: HashSet<String>) -> Self {
        self.categories = Some(categories);
        self
    }

    /// Set context requirement.
    pub fn with_require_context(mut self, require: bool) -> Self {
        self.require_context = require;
        self
    }

    /// Set minimum confidence.
    pub fn with_min_confidence(mut self, min_confidence: f64) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Set allowlist.
    pub fn with_allowlist(mut self, allowlist: Allowlist) -> Self {
        self.allowlist = Some(allowlist);
        self
    }

    /// Process a single file.
    pub fn process_file(&self, path: &Path) -> PipelineResult {
        let start = Instant::now();
        let file_path = path.display().to_string();

        // Check file size
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return PipelineResult {
                    file_path,
                    matches: vec![],
                    format_detected: "unknown".into(),
                    duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                    error: Some(format!("Cannot read file: {e}")),
                    file_size_bytes: 0,
                    extracted_text_length: 0,
                };
            }
        };

        if metadata.len() as usize > self.max_file_size {
            return PipelineResult {
                file_path,
                matches: vec![],
                format_detected: "unknown".into(),
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                error: Some(format!(
                    "File too large: {} bytes (max {})",
                    metadata.len(),
                    self.max_file_size
                )),
                file_size_bytes: metadata.len(),
                extracted_text_length: 0,
            };
        }

        // Try extractor first (handles DOCX, XLSX, PDF, EML, etc.), fall back to plain text
        let file_path_str = path.display().to_string();
        let (text, format) = match crate::extractors::extract_text(&file_path_str) {
            Ok(result) => (result.text, result.format),
            Err(_) => {
                // Extractor failed, try reading as plain text
                match fs::read_to_string(path) {
                    Ok(t) => (t, detect_format(path)),
                    Err(e) => {
                        return PipelineResult {
                            file_path,
                            matches: vec![],
                            format_detected: "binary".into(),
                            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                            error: Some(format!("Cannot read file: {e}")),
                            file_size_bytes: metadata.len(),
                            extracted_text_length: 0,
                        };
                    }
                }
            }
        };

        let text_len = text.len();

        let config = ScanConfig {
            categories: self.categories.clone(),
            require_context: self.require_context,
            min_confidence: self.min_confidence,
            deduplicate: self.deduplicate,
            ..Default::default()
        };

        let output = match scanner::scan_text_with_config(&text, &config) {
            Ok(o) => o,
            Err(e) => {
                return PipelineResult {
                    file_path,
                    matches: vec![],
                    format_detected: format,
                    duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                    error: Some(format!("Scan error: {e}")),
                    file_size_bytes: metadata.len(),
                    extracted_text_length: text_len,
                };
            }
        };
        if output.truncated {
            tracing::warn!(file = %file_path, "Scan results truncated (timeout or match cap)");
        }
        let mut matches = output.matches;

        // Apply allowlist
        if let Some(ref allowlist) = self.allowlist {
            matches.retain(|m| !allowlist.is_suppressed(m));
        }

        PipelineResult {
            file_path,
            matches,
            format_detected: format,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            error: None,
            file_size_bytes: metadata.len(),
            extracted_text_length: text_len,
        }
    }

    /// Process multiple files in parallel using rayon.
    pub fn process_files(&self, paths: &[PathBuf]) -> Vec<PipelineResult> {
        paths
            .par_iter()
            .filter(|p| {
                if let Some(ref al) = self.allowlist {
                    !al.should_skip_path(&p.display().to_string())
                } else {
                    true
                }
            })
            .map(|p| self.process_file(p))
            .collect()
    }

    /// Process all files in a directory recursively.
    pub fn process_directory(&self, dir: &Path, recursive: bool) -> Vec<PipelineResult> {
        let paths = collect_files(dir, recursive);
        self.process_files(&paths)
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect file format from extension.
fn detect_format(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("txt") | Some("log") | Some("csv") => "text".into(),
        Some("json") => "json".into(),
        Some("xml") | Some("html") | Some("htm") => "xml".into(),
        Some("pdf") => "pdf".into(),
        Some("docx") => "docx".into(),
        Some("xlsx") => "xlsx".into(),
        Some("pptx") => "pptx".into(),
        Some("eml") | Some("msg") => "email".into(),
        Some("py") | Some("rs") | Some("js") | Some("ts") | Some("go") | Some("java") => {
            "source_code".into()
        }
        Some(ext) => ext.to_string(),
        None => "unknown".into(),
    }
}

/// Collect all text files in a directory.
fn collect_files(dir: &Path, recursive: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return files,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.file_name().map(|n| n.to_string_lossy().starts_with('.')).unwrap_or(false) {
            continue; // Skip hidden files
        }

        if path.is_dir() {
            if recursive {
                files.extend(collect_files(&path, true));
            }
        } else if path.is_file() {
            files.push(path);
        }
    }

    files
}

/// Export results as JSON.
pub fn results_to_json(results: &[PipelineResult], pretty: bool) -> crate::Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(results)?)
    } else {
        Ok(serde_json::to_string(results)?)
    }
}

fn escape_csv_field(field: &str) -> String {
    let needs_quoting = field.contains(',') || field.contains('"') || field.contains('\n')
        || field.contains('\r')
        || field.starts_with('=') || field.starts_with('+')
        || field.starts_with('-') || field.starts_with('@');
    if needs_quoting {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Export results as CSV.
pub fn results_to_csv(results: &[PipelineResult]) -> String {
    let mut output = String::from("file_path,match_count,format,duration_ms,error\n");
    for r in results {
        output.push_str(&format!(
            "{},{},{},{:.2},{}\n",
            escape_csv_field(&r.file_path),
            r.match_count(),
            escape_csv_field(&r.format_detected),
            r.duration_ms,
            escape_csv_field(r.error.as_deref().unwrap_or(""))
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_pipeline_default() {
        let pipeline = Pipeline::default();
        assert_eq!(pipeline.max_file_size, DEFAULT_MAX_FILE_SIZE);
        assert!(!pipeline.require_context);
    }

    #[test]
    fn test_pipeline_builder() {
        let pipeline = Pipeline::new()
            .with_max_file_size(1024)
            .with_require_context(true)
            .with_min_confidence(0.5);
        assert_eq!(pipeline.max_file_size, 1024);
        assert!(pipeline.require_context);
        assert_eq!(pipeline.min_confidence, 0.5);
    }

    #[test]
    fn test_process_file_with_sensitive_data() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        let mut f = fs::File::create(&file_path).unwrap();
        writeln!(f, "Contact email: test@example.com").unwrap();

        let pipeline = Pipeline::new();
        let result = pipeline.process_file(&file_path);
        assert!(result.success());
        assert!(result.match_count() > 0);
        assert!(["text", "txt"].contains(&result.format_detected.as_str()));
        assert!(result.file_size_bytes > 0);
    }

    #[test]
    fn test_process_file_clean() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("clean.txt");
        let mut f = fs::File::create(&file_path).unwrap();
        writeln!(f, "Hello world, no sensitive data here.").unwrap();

        let pipeline = Pipeline::new();
        let result = pipeline.process_file(&file_path);
        assert!(result.success());
    }

    #[test]
    fn test_process_file_not_found() {
        let pipeline = Pipeline::new();
        let result = pipeline.process_file(Path::new("/nonexistent/file.txt"));
        assert!(!result.success());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_process_file_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("big.txt");
        let mut f = fs::File::create(&file_path).unwrap();
        f.write_all(&vec![b'a'; 1024]).unwrap();

        let pipeline = Pipeline::new().with_max_file_size(100);
        let result = pipeline.process_file(&file_path);
        assert!(!result.success());
        assert!(result.error.as_ref().unwrap().contains("too large"));
    }

    #[test]
    fn test_process_directory() {
        let dir = tempfile::tempdir().unwrap();
        let f1 = dir.path().join("a.txt");
        let f2 = dir.path().join("b.txt");
        fs::write(&f1, "Email: test@example.com").unwrap();
        fs::write(&f2, "Clean text here").unwrap();

        let pipeline = Pipeline::new();
        let results = pipeline.process_directory(dir.path(), false);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success()));
    }

    #[test]
    fn test_process_files_parallel() {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<PathBuf> = (0..5).map(|i| {
            let p = dir.path().join(format!("file{i}.txt"));
            fs::write(&p, format!("File {i}: contact@test.com")).unwrap();
            p
        }).collect();

        let pipeline = Pipeline::new();
        let results = pipeline.process_files(&paths);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_detect_format() {
        assert_eq!(detect_format(Path::new("test.txt")), "text");
        assert_eq!(detect_format(Path::new("data.json")), "json");
        assert_eq!(detect_format(Path::new("doc.pdf")), "pdf");
        assert_eq!(detect_format(Path::new("code.rs")), "source_code");
        assert_eq!(detect_format(Path::new("noext")), "unknown");
    }

    #[test]
    fn test_results_to_json() {
        let results = vec![PipelineResult {
            file_path: "test.txt".into(),
            matches: vec![],
            format_detected: "text".into(),
            duration_ms: 1.5,
            error: None,
            file_size_bytes: 100,
            extracted_text_length: 100,
        }];
        let json = results_to_json(&results, false).unwrap();
        assert!(json.contains("test.txt"));
    }

    #[test]
    fn test_results_to_csv() {
        let results = vec![PipelineResult {
            file_path: "test.txt".into(),
            matches: vec![],
            format_detected: "text".into(),
            duration_ms: 1.5,
            error: None,
            file_size_bytes: 100,
            extracted_text_length: 100,
        }];
        let csv = results_to_csv(&results);
        assert!(csv.starts_with("file_path,"));
        assert!(csv.contains("test.txt"));
    }

    #[test]
    fn test_escape_csv_field() {
        assert_eq!(escape_csv_field("simple"), "simple");
        assert_eq!(escape_csv_field("has,comma"), "\"has,comma\"");
        assert_eq!(escape_csv_field("has\"quote"), "\"has\"\"quote\"");
        assert_eq!(escape_csv_field("=formula"), "\"=formula\"");
    }

    #[test]
    fn test_pipeline_result_methods() {
        let r = PipelineResult {
            file_path: "f.txt".into(),
            matches: vec![],
            format_detected: "text".into(),
            duration_ms: 0.0,
            error: None,
            file_size_bytes: 0,
            extracted_text_length: 0,
        };
        assert!(r.success());
        assert_eq!(r.match_count(), 0);
    }

    #[test]
    fn test_collect_files_skips_hidden() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("visible.txt"), "data").unwrap();
        fs::write(dir.path().join(".hidden"), "data").unwrap();

        let files = collect_files(dir.path(), false);
        assert_eq!(files.len(), 1);
        assert!(files[0].file_name().unwrap().to_str().unwrap() == "visible.txt");
    }
}
