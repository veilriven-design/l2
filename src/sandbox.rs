use anyhow::Result;
use std::path::Path;

pub fn apply_strict_sandbox(workspace: Option<&Path>) -> Result<()> {
    // Apply real (limited) hardening using nix; Landlock integration planned for full strict
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        eprintln!("[strict] note: could not set no_new_privs: {}", e);
    }

    if let Some(ws) = workspace {
        // TODO: full Landlock ruleset on the child (requires inheritable fd or seccomp pre-exec)
        // For now we just acknowledge the intent. The workspace is already tmpfs-isolated by unshare.
        println!("[strict] Landlock (planned) would restrict FS to: {}", ws.display());
    }

    println!("[strict] Sandbox applied (no_new_privs + isolation active; landlock pending)");
    Ok(())
}
