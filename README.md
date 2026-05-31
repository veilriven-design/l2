**l2** is the focused Latticra substrate.

**⚠️ Experimental Prototype — Not Yet High Assurance**

This is an early-stage experimental prototype. **It is not a true high-assurance substrate.**

The current implementation runs on ordinary Linux using namespaces for isolation. While it demonstrates some of the intended shape and developer experience, it does **not** provide strong security guarantees. Do not use this for anything security-critical, production workloads, or sensitive workloads.

The long-term intent is to build a minimal, high-assurance system with a much stronger foundation (targeting seL4). That work has not been done yet.

---

A minimal high-assurance system for creating, using, and destroying strongly isolated execution contexts on demand — driven from the terminal.

**Status**: Working persistent host prototype. Real Linux namespace isolation for `exec`. State survives across separate terminal commands. Narrow L2P protocol specified.

## The Core Idea

From an ordinary terminal on any host, you create isolated "systems" (containment contexts), put only what you intend into them, run work inside them, retrieve results, and destroy them cleanly.

Everything crosses the boundary explicitly through a narrow, auditable surface. No background daemons. No ambient authority.

## Public Interface (the only surface)

All interaction happens through the `l2` command-line tool and the narrow `l2_sys_*` functions it drives.

Primary operations:

- `l2 create <name> [--policy ...]` — create a new isolated system
- `l2 put <sys> <name> [--type <type>] [--content <text>]` — place something inside a system
- `l2 exec <name> <what> [args]` — run work inside the system
- `l2 get <name> <object>` — retrieve results or artifacts
- `l2 list <name>` — inspect what the system currently holds
- `l2 revoke <name> <grant>` — remove specific authority
- `l2 destroy <name>` — tear down the system with no residual state
- `l2 sel4-setup` — one-command bootstrap of a seL4/Microkit development environment (SDK + optional container)

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

- An early experimental prototype exploring the shape of a high-assurance containment primitive.
- Works from a normal terminal on ordinary developer machines today (host mechanisms with real isolation), with a clear path to seL4-backed strong isolation.

## What l2 Is Not

- A general-purpose OS or container platform
- An always-running service or daemon
- A full effect system, lattice framework, or modeling environment
- A packaging, distribution, or installer system
- A secure or high-assurance system suitable for production or sensitive use

## Try It Now (Persistent Host Prototype)

The prototype now persists state to disk, so you can use it like a normal tool across multiple terminal commands.

```bash
cargo build --release

# These commands can be run in separate shells / terminals
./target/release/l2 create review-agent --policy strict
./target/release/l2 put review-agent main.rs --type code --content 'fn main() { println!("hello from inside"); }'
./target/release/l2 list review-agent
./target/release/l2 exec review-agent 'echo hello from inside the substrate'
./target/release/l2 get review-agent main.rs
./target/release/l2 destroy review-agent

# JSON for scripting / tools
l2 --json list
```

State is stored in `~/.l2/state.json`. You can override it with `L2_DATA_DIR=/path l2 ...`

See `STATUS.md`, `docs/PROTOCOL.md`, and `docs/TERMINAL_INTERFACE.md`.

## seL4 / Microkit Development Setup

`l2` ships with a full-featured setup command for the seL4 track:

```bash
l2 sel4-setup
```

This creates `~/l2-sel4-workspace` and:

- Downloads the official prebuilt Microkit SDK (no container required for basic use)
- Clones the Microkit source for reference
- On RHEL/Fedora/Rocky/AlmaLinux systems (where native cross-compilers are painful), it automatically detects podman and offers to set up the official seL4 development container (`DOCKER=podman make user`) with a live spinner + status line so you can see it's still working.

After running it, read the generated guide in the workspace:

```bash
cat ~/l2-sel4-workspace/README-l2-sel4.md
```

This gives you the cleanest current path into real seL4/Microkit development while the host prototype remains usable for day-to-day work.

## Repository

- License: BSD-2-Clause
- High-assurance posture: see `SECURITY.md`
- Contribution rules: see `CONTRIBUTING.md`

This is the narrow, terminal-native realization of the Latticra substrate idea.
