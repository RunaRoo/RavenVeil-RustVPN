//! logger.rs - A robust, structured logger.

use anyhow::{Context, Result};
use chrono::Utc;
use log::{LevelFilter, Log, Metadata, Record};
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

/// A logger that writes structured JSON logs to file and human-readable text to stdout.
pub struct StructuredLogger {
    log_file: Option<Arc<Mutex<File>>>,
    log_to_stdout: bool,
    max_level: LevelFilter,
}

impl StructuredLogger {
    /// Creates a new logger instance.
    pub fn new(
        log_path: Option<&str>,
        log_to_stdout: bool,
        max_level: LevelFilter,
    ) -> Result<Self, io::Error> {
        let log_file = match log_path {
            Some(path) if !path.is_empty() => {
                let file = OpenOptions::new().create(true).append(true).open(path)?;
                Some(Arc::new(Mutex::new(file)))
            }
            _ => None,
        };

        Ok(StructuredLogger {
            log_file,
            log_to_stdout,
            max_level,
        })
    }

    /// Initializes and sets the global logger for the application.
    pub fn init(
        log_level: LevelFilter,
        log_path: Option<&str>,
        log_to_stdout: bool,
    ) -> Result<()> {
        let logger = Self::new(log_path, log_to_stdout, log_level)
            .with_context(|| format!("Failed to create logger with path: {:?}", log_path))?;

        log::set_boxed_logger(Box::new(logger))
            .with_context(|| "Failed to set global logger")?;

        log::set_max_level(log_level);
        Ok(())
    }
}

impl Log for StructuredLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let timestamp = Utc::now();

        // 1. Console Output: Human Readable
        if self.log_to_stdout {
            // ANSI Colors
            let (color_code, level_str) = match record.level() {
                log::Level::Error => ("\x1b[31m", "ERROR"), // Red
                log::Level::Warn => ("\x1b[33m", "WARN "),  // Yellow
                log::Level::Info => ("\x1b[32m", "INFO "),  // Green
                log::Level::Debug => ("\x1b[34m", "DEBUG"), // Blue
                log::Level::Trace => ("\x1b[35m", "TRACE"), // Magenta
            };
            let reset = "\x1b[0m";
            let ts_str = timestamp.format("%H:%M:%S");

            println!("{} {}{}{} [{}] {}",
                     ts_str,
                     color_code, level_str, reset,
                     record.target(),
                     record.args()
            );
        }

        // 2. File Output: JSON
        if let Some(file) = &self.log_file {
            if let Ok(mut guard) = file.lock() {
                let log_data = json!({
                    "timestamp": timestamp.to_rfc3339(),
                    "level": record.level().to_string(),
                    "target": record.target(),
                    "message": record.args().to_string(),
                    "module": record.module_path().unwrap_or(""),
                    "file": record.file().unwrap_or(""),
                    "line": record.line(),
                });

                if let Ok(json_str) = serde_json::to_string(&log_data) {
                    let _ = writeln!(guard, "{}", json_str);
                }
            }
        }
    }

    fn flush(&self) {
        if let Some(file) = &self.log_file {
            if let Ok(mut guard) = file.lock() {
                let _ = guard.flush();
            }
        }
        let _ = io::stdout().flush();
    }
}