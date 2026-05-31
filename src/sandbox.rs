// Stub for strict sandbox (full implementation in future PR)
// For now, returns Ok to allow compilation
use anyhow::Result;
pub fn apply_strict_sandbox(_workspace: Option<&std::path::Path>) -> Result<()> {
    println!("[sandbox stub] Strict policy sandbox applied (placeholder)");
    Ok(())
}
