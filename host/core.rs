//! l2-core (future separate binary)
//!
//! This will become the out-of-process core that speaks L2P v1 over stdio
//! or a unix socket, implementing the narrow protocol defined in docs/PROTOCOL.md.
//!
//! For now this is a placeholder. The current combined prototype in src/main.rs
//! demonstrates the surface and real isolation while we split.

/* Planned structure:
 * - Read JSON lines from stdin (L2P requests)
 * - Dispatch to real core implementation (C or Rust)
 * - Write responses to stdout
 * - Manage actual isolated contexts (namespaces today, seL4 later)
 */

fn main() {
    eprintln!("l2-core: out-of-process L2P core (stub). See docs/PROTOCOL.md");
    eprintln!("The combined prototype in `l2` still provides the working experience.");
}
