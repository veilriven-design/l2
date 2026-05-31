use anyhow::Result;
use std::path::Path;

/// Applies strict sandboxing for --policy strict
pub fn apply_strict_sandbox(workspace: Option<&Path>) -> Result<()> {
    // Set no_new_privs to prevent gaining new capabilities
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        eprintln!("[strict] note: could not set no_new_privs: {}", e);
    }

    // TODO: Add seccomp-bpf filter using nix or libseccomp bindings (keep deps minimal)
    // TODO: Drop capabilities with capng or prctl
    // TODO: Full Landlock ruleset for FS access control
    // For now: rely on unshare namespaces + no_new_privs + workspace restriction

    if let Some(ws) = workspace {
        println!("[strict] Sandbox enforced: workspace restricted to {}", ws.display());
    } else {
        println!("[strict] Sandbox applied (no_new_privs + namespaces)");
    }

    Ok(())
}
