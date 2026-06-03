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
    // Intentionally silent on failure — audit is best-effort evidence (mature Host + L2P still treat it as non-fatal for robustness).
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
/// Uses the centralized l2::data_dir (which handles L2_DATA_DIR first, then SUDO_USER,
/// then HOME) so audit.log always lands in the same place as state + reports.
/// This was a source of inconsistency in prior versions (mixed ~/.l2 and L2D).
pub fn path() -> PathBuf {
    // Prefer the shared implementation in the library for perfect L2_DATA_DIR + sudo consistency.
    // Fall back to a safe default only on error (should be rare).
    match l2::audit_log_path() {
        Ok(p) => p,
        Err(_) => {
            // Last resort (e.g. no HOME and no L2_DATA_DIR) — use cwd/.l2 to avoid panic.
            std::path::PathBuf::from(".l2").join("audit.log")
        }
    }
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
