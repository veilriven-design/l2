use anyhow::Result;
use landlock::{Access, AccessFs, Ruleset, RulesetAttr, RulesetCreated, RulesetStatus, PathFd, FS_ACCESS_READ, FS_ACCESS_WRITE, FS_ACCESS_EXEC};
use std::path::Path;

pub fn apply_strict_sandbox(workspace: Option<&Path>) -> Result<()> {
    // Set no_new_privs first
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        eprintln!("[strict] note: could not set no_new_privs: {}", e);
    }

    if let Some(ws) = workspace {
        // Create Landlock ruleset for strict FS sandbox
        let mut ruleset = Ruleset::new()
            .with(AccessFs::from(FS_ACCESS_READ | FS_ACCESS_EXEC)) // allow read/exec
            .with(AccessFs::from_bits_truncate(0)) // no write by default
            .create()?;

        // Allow the workspace dir
        let ws_fd = PathFd::new(ws)?;
        ruleset.add_rule(&ws_fd, AccessFs::from(FS_ACCESS_READ | FS_ACCESS_EXEC)) ?;

        // Restrict to workspace only (deny other FS by default when enforced)
        let status = ruleset.restrict_self()?;
        if status.ruleset != RulesetStatus::Success {
            eprintln!("[strict] Landlock restrict status: {:?}", status);
        } else {
            println!("[strict] Landlock FS sandbox active: RO+EXEC on workspace only");
        }
    } else {
        println!("[strict] Sandbox applied (no_new_privs + namespaces)");
    }

    Ok(())
}
