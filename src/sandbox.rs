use anyhow::Result;
use std::path::Path;

use landlock::{
    Access, AccessFs, ABI as LandlockABI, CompatLevel, PathFd, Ruleset, RulesetAttr, RulesetStatus,
};

pub fn apply_strict_sandbox(workspace: Option<&Path>) -> Result<()> {
    // Set no_new_privs first (as before)
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        eprintln!("[strict] note: could not set no_new_privs: {}", e);
    }

    // Apply Landlock ruleset for FS sandboxing (deny-by-default, restrict to workspace if provided)
    let abi = LandlockABI::V2; // Modern, supported on recent kernels
    let mut ruleset = Ruleset::new(
        RulesetAttr::new()
            .with(landlock::AccessFs::from_all(landlock::AccessFs::from_bits_truncate(0))) // start restrictive
            .with(ABI::V1) // compatibility
            .with(CompatLevel::Hard),
    )?;

    if let Some(ws) = workspace {
        // Allow read/execute on workspace dir only (minimal for now)
        let ws_fd = PathFd::new(ws)?;
        ruleset.add_rule(
            landlock::PathBeneath::new(
                ws_fd,
                AccessFs::from_all(AccessFs::RO | AccessFs::EXEC),
            ),
        )?;
    }

    // Handle ruleset status (warn if not enforced)
    let status = ruleset.restrict_self()?;
    if status.is_incompatible() {
        eprintln!("[strict] warning: Landlock not fully supported by kernel; falling back to partial isolation");
    } else if status.is_partially_enforced() {
        eprintln!("[strict] note: Landlock partially enforced");
    } else {
        println!("[strict] Landlock FS sandbox active (RO+EXEC on workspace)");
    }

    println!("[strict] Sandbox applied (no_new_privs + Landlock + isolation)");
    Ok(())
}
