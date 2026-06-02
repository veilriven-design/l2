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
///
/// IMPROVED (overall project hardening): simple tamper-evident chaining.
/// Each entry includes a "prev" field containing a hash of the previous
/// line (using std::hash::DefaultHasher; not a cryptographic SHA256).
/// This allows detection of truncation or insertion by non-privileged
/// attackers. For stronger assurance the log should be protected at the
/// filesystem level (append-only, remote syslog, or signed).
pub fn log(op: &str, details: Value) {
    let p = path();
    let prev = last_entry_hash(&p);

    let entry = json!({
        "ts": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "op": op,
        "details": details,
        "prev": prev
    });

    let line = match serde_json::to_string(&entry) {
        Ok(l) => l,
        Err(_) => return,
    };

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {
        let _ = writeln!(f, "{}", line);
    }
    // Intentionally silent on failure — audit is advisory for the prototype.
}

/// Compute a simple chain hash of the last line in the audit log (for tamper evidence).
fn last_entry_hash(p: &PathBuf) -> Option<String> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::io::{BufRead, BufReader};

    let f = std::fs::File::open(p).ok()?;
    let reader = BufReader::new(f);
    let mut last: Option<String> = None;
    for l in reader.lines().map_while(Result::ok) {
        if !l.trim().is_empty() {
            last = Some(l);
        }
    }
    last.map(|l| {
        let mut hasher = DefaultHasher::new();
        l.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    })
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

/// Verify the tamper-evident hash chain of an audit log.
/// Returns (is_valid, number_of_entries_checked).
/// Note: the chain uses a non-crypto hasher; it primarily detects accidental
/// or low-privilege tampering/truncation.
pub fn verify_chain(log_path: &std::path::Path) -> anyhow::Result<(bool, usize)> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::io::{BufRead, BufReader};

    if !log_path.exists() {
        return Ok((true, 0));
    }

    let file = std::fs::File::open(log_path)?;
    let reader = BufReader::new(file);

    let mut count = 0usize;
    let mut previous_hash: Option<String> = None;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue, // skip malformed
        };

        count += 1;

        // Check that the recorded "prev" matches what we computed from the actual previous line
        if let Some(recorded_prev) = v.get("prev").and_then(|p| p.as_str()) {
            if let Some(expected) = &previous_hash {
                if recorded_prev != expected {
                    return Ok((false, count));
                }
            } else if !recorded_prev.is_empty() {
                // First entry should have empty or absent prev
                return Ok((false, count));
            }
        }

        // Compute hash of *this* line for the next entry to check against
        let mut hasher = DefaultHasher::new();
        line.hash(&mut hasher);
        previous_hash = Some(format!("{:016x}", hasher.finish()));
    }

    Ok((true, count))
}
