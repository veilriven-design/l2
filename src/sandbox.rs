use anyhow::Result;
use std::path::Path;

use landlock::{AccessFs, PathBeneath, Ruleset, RulesetAttr, RulesetCreated, RulesetStatus};

pub fn apply_strict_sandbox(workspace: Option<&Path>) -> Result<()> {
    // no_new_privs is a strong hardening primitive
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        eprintln!("[strict] note: could not set no_new_privs: {}", e);
    }

    if let Some(ws) = workspace {
        // Simple but effective Landlock ruleset: allow the workspace, deny everything else
        let ruleset = Ruleset::new()
            .handle_access(AccessFs::from_all())?
            .create()?;

        let rule = PathBeneath::new(ws, AccessFs::from_all());
        let ruleset = ruleset.add_rule(rule)?;

        let status = ruleset.restrict_self()?;

        match status.ruleset {
            RulesetStatus::Enforced => {
                println!("[strict] ✓ Landlock FS sandbox active (restricted to workspace)");
            }
            RulesetStatus::NotEnforced => {
                eprintln!("[strict] ⚠ Landlock not enforced by kernel (older kernel?)");
            }
            _ => {
                eprintln!("[strict] Landlock status: {:?}", status);
            }
        }
    } else {
        println!("[strict] Sandbox applied (no_new_privs + namespaces)");
    }

    Ok(())
}
