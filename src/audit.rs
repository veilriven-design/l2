//! Minimal append-only audit log for authority events.
//!
//! Fulfills the "Evidence and audit" requirement in SECURITY.md.
//! All create/put/exec/destroy/revoke operations that cross the boundary
//! should call this (best-effort only — never blocks the main operation).
//!
//! Format: one JSON object per line (JSONL).
//! Location: $L2_DATA_DIR/audit.log (or ~/.l2/audit.log), respecting SUDO_USER.

use chrono::Utc;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

/// Log an authority event. This is best-effort and must never panic or
/// cause the calling operation to fail.
pub fn log(op: &str, details: Value) {
    let entry = json!({
        "ts": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "op": op,
        "details": details
    });

    let line = match serde_json::to_string(&entry) {
        Ok(l) => l,
        Err(_) => return,
    };

    let path = path();
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}", line);
    }
    // Intentionally silent on failure — audit is advisory for the prototype.
}

/// Returns the full path to the audit log file for the current user/context.
/// Public so the CLI can implement `l2 audit` without duplicating logic.
pub fn path() -> PathBuf {
    // Mirror the logic in main.rs::data_dir() so SUDO_USER works correctly
    // after privilege escalation for exec.
    if let Ok(dir) = std::env::var("L2_DATA_DIR") {
        return PathBuf::from(dir).join("audit.log");
    }

    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if let Some(home) = get_home_for_user(&sudo_user) {
            return PathBuf::from(home).join(".l2").join("audit.log");
        }
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".l2").join("audit.log")
}

fn get_home_for_user(username: &str) -> Option<String> {
    let output = std::process::Command::new("getent")
        .args(["passwd", username])
        .output()
        .ok()?;
    let line = std::str::from_utf8(&output.stdout).ok()?;
    line.split(':').nth(5).map(|h| h.trim().to_string())
}
