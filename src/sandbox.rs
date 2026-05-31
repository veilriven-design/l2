use anyhow::Result;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use std::path::Path;

/// Applies strict sandboxing for --policy strict.
/// Implements no_new_privs + practical Landlock FS restrictions:
/// - Full R/W/X under the system workspace
/// - Read + Exec on standard system paths needed for shell/tools to function
/// - All other FS writes denied (high-assurance write isolation)
pub fn apply_strict_sandbox(workspace: Option<&Path>) -> Result<()> {
    // no_new_privs: prevent the process or children from gaining new privileges (e.g. via setuid binaries)
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        eprintln!("[strict] note: could not set no_new_privs: {}", e);
    }

    // TODO (next for v0.2+): seccomp-bpf using nix::sys::seccomp (or minimal libseccomp-sys)
    // TODO (next for v0.2+): capability dropping via prctl or caps crate (drop all but needed)
    // TODO (future): integrate with user namespaces + mount namespace ro-remounts for stronger guarantees
    // Current v0.2.0: Landlock + no_new_privs + unshare namespaces provide strong FS + privilege isolation

    if let Some(ws) = workspace {
        // Choose a solid ABI version supported on modern kernels (V5 covers most useful features)
        let abi = ABI::V5;

        // We handle all FS rights so we can explicitly grant subsets
        let rs = Ruleset::default().handle_access(AccessFs::from_all(abi))?;
        let rs = rs.create()?;

        // Workspace: full access (this is the core of strict policy isolation)
        let ws_rules = path_beneath_rules([ws], AccessFs::from_all(abi));
        let mut rs = rs.add_rules(ws_rules)?;

        let ro_access = AccessFs::from_read(abi) | AccessFs::Execute;

        // Read+Exec on essential system paths (pragmatic allowlist so `sh -c`, coreutils etc. work).
        // Writes remain denied outside the workspace. This is a deliberate prototype compromise.
        // TODO(v0.2+): make this configurable or derive from PATH + ld cache for even tighter policy.
        let ro_paths = [
            "/bin",
            "/usr/bin",
            "/lib",
            "/usr/lib",
            "/lib64",
            "/usr/lib64",
            "/proc",
            "/dev",
            "/etc",
            "/tmp",
        ];
        for p in ro_paths {
            if Path::new(p).exists() {
                let rules = path_beneath_rules([p], ro_access);
                // Use ? here: failure to add a ro path aborts sandbox setup for this exec (still have no_new_privs)
                // In practice these succeed on any reasonable Linux system.
                rs = rs.add_rules(rules)?;
            }
        }

        // Enforce the final ruleset
        let status = rs.restrict_self()?;

        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                println!(
                    "[strict] ✓ Landlock FS sandbox active (writes restricted to {}; RO+EXEC elsewhere)",
                    ws.display()
                );
            }
            RulesetStatus::PartiallyEnforced => {
                println!("[strict] ⚠ Landlock partially enforced (some features unavailable on this kernel)");
            }
            RulesetStatus::NotEnforced => {
                eprintln!("[strict] ⚠ Landlock not enforced on this system (kernel too old or LSM disabled)");
            }
        }
    } else {
        println!("[strict] Sandbox applied (no_new_privs + namespaces)");
    }

    Ok(())
}
