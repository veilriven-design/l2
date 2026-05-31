**l2** is the focused Latticra substrate.

A minimal high-assurance system for creating, using, and destroying strongly isolated execution contexts on demand — driven from the terminal.

**Status**: Working Rust host prototype CLI. Real Linux namespace isolation for execution. Narrow L2P protocol specified. Clear path to disciplined C core + seL4 backend.

## The Core Idea

From an ordinary terminal on any host, you create isolated "systems" (containment contexts), put only what you intend into them, run work inside them, retrieve results, and destroy them cleanly.

Everything crosses the boundary explicitly through a narrow, auditable surface. No background daemons. No ambient authority.

## Public Interface (the only surface)

All interaction happens through the `l2` command-line tool and the narrow `l2_sys_*` functions it drives.

Primary operations:

- `l2 create <name> [--policy ...]` — create a new isolated system
- `l2 put <name> <object> ...` — place code, data, or credentials inside
- `l2 exec <name> <what> [args]` — run work inside the system
- `l2 get <name> <object>` — retrieve results or artifacts
- `l2 list <name>` — inspect what the system currently holds
- `l2 revoke <name> <grant>` — remove specific authority
- `l2 destroy <name>` — tear down the system with no residual state

The terminal is the universal interface. GUIs, IDEs, and higher tools are built on top of this (later, if at all).

## Design Principles

- **Terminal first.** The experience must feel direct, precise, and natural from a shell — like a well-crafted CLI/TUI.
- **Tiny interface.** The public surface is deliberately small and stable.
- **Dynamic and on-demand.** Systems exist only when you need them.
- **Total destruction.** Destroying a system leaves no residual authority or observable state.
- **Minimal TCB.** seL4 (or the strongest available host mechanism) is the root of trust. The userland core stays tiny and disciplined.
- **Restraint over features.** We delete or avoid adding code more often than we add it.
- **Explicit everything.** No implicit flows, no ambient capabilities, no hidden channels.

## What l2 Is

- A high-assurance containment primitive for MCP servers, agentic tools, build tasks, and developer workflows.
- C with rigorous memory safety guards in the core (future).
- Works from a normal terminal on ordinary developer machines today (host mechanisms with real isolation), with a clear path to seL4-backed strong isolation.

## What l2 Is Not

- A general-purpose OS or container platform
- An always-running service or daemon
- A full effect system, lattice framework, or modeling environment
- A packaging, distribution, or installer system

## Try It Now (Host Prototype)

The first working pieces are implemented as a Rust CLI. Real namespace isolation is active for `exec`.

```bash
# Build
cargo build --release

# Create and use a system
./target/release/l2 create review-agent --policy strict
./target/release/l2 put review-agent code main.rs --content "fn main() { ... }"
./target/release/l2 list review-agent
./target/release/l2 exec review-agent "echo hello from inside"
./target/release/l2 get review-agent result
./target/release/l2 destroy review-agent

# JSON mode for scripts
l2 --json list
```

See `STATUS.md` for the live checklist and `docs/PROTOCOL.md` + `docs/TERMINAL_INTERFACE.md` for the foundations.

## Repository

- License: BSD-2-Clause
- High-assurance posture: see `SECURITY.md`
- Contribution rules: see `CONTRIBUTING.md`

This is the narrow, terminal-native realization of the Latticra substrate idea. Everything else was left behind.
