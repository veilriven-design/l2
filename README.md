# l2 — Minimal High-Assurance System Substrate (v0.2.1)

Terminal-first CLI for creating, using, and destroying strongly isolated execution contexts. Narrow surface. Built for high-assurance with seL4 as the root of trust.

**Linux prototype** — ready for immediate use and validation.  
**seL4/Microkit** — the production/high-assurance path.

## Install

### Recommended: cargo install (global)
```bash
git clone https://github.com/veilriven-design/l2.git
cd l2
git checkout v0.2.1
cargo install --path . --force
l2 --help
```

### From source (build only)
```bash
git clone https://github.com/veilriven-design/l2.git
cd l2
git checkout v0.2.1
cargo build --release
./target/release/l2 --help
# (or add target/release to PATH, or use the install command above)
```

Override state location anytime with `L2_DATA_DIR=/path l2 ...`.

## Quick Start

```bash
# Create an isolated system with full Landlock + no_new_privs enforcement
l2 create my-agent --policy strict

# Store data or code inside it (persisted in ~/.l2 or $L2_DATA_DIR)
l2 put my-agent task.sh --type code --content 'echo "Hello from l2"'

# Execute inside the isolated environment (strict policy applies Landlock)
# (l2 auto-escalates via sudo if namespace isolation requires root)
l2 exec my-agent 'sh task.sh'

# New simpler forms (auto-dispatch + oneshot)
l2 exec my-agent task.sh          # auto-dispatches for known extensions / shebangs
echo 'print("hi from isolated python")' > /tmp/hello.py
l2 exec /tmp/hello.py             # oneshot: creates temp system, runs, destroys

l2 destroy my-agent
```

**Important:** `put --type code` stores the content as a file.

`l2 exec` now supports convenient forms:
- Bare names inside a system are auto-dispatched when possible (`l2 exec mysys hello.py` → `python3 hello.py`)
- One-shot execution: `l2 exec hello.py` (local file) creates a temporary isolated system, runs the code (respecting `--policy`), then destroys it completely.

Shebang (`#!`) is the primary way to support "any" language on the host prototype.

Compiled languages (C, C++, Rust) now get self-contained compile + run + cleanup wrappers in oneshot mode, so `l2 exec hello.rs` works even without an explicit build command.

### Language Execution & One-shot Mode

```bash
# One-shot (recommended for quick experiments / AI-generated code)
l2 exec /tmp/agent-task.py

# With explicit policy for high-assurance / MCP workloads
l2 exec --policy strict-mcp /tmp/untrusted-agent.py

# Inside a persistent system with auto-dispatch
l2 create review-agent --policy strict
l2 put review-agent review.py --type code --content '...'
l2 exec review-agent review.py     # becomes "python3 review.py"
```

High-assurance seL4 development environment:
```bash
l2 sel4-setup
cat ~/l2-sel4-workspace/README-l2-sel4.md
```

## What v0.2.0 Delivers

- Real `strict` policy: Landlock LSM restricts the process to read+exec on the system workspace only (plus minimal system paths). Writes outside are denied by the kernel.
- `no_new_privs` + unshare namespaces for every `exec`.
- All core commands work with persistence across shells.
- One-command seL4/Microkit bootstrap (`l2 sel4-setup`).

See `CHANGELOG.md` and the v0.1.0 tag for the previous baseline:
```bash
git checkout v0.1.0
```

## Common Commands

| Command                  | Description |
|--------------------------|-------------|
| `l2 create <name> [--policy strict\|default]` | Create isolated system |
| `l2 put <sys> <name> --content '...' [--type code\|data]` | Store object |
| `l2 get <sys> <name>`    | Retrieve object |
| `l2 exec <sys> [command]` | Run code inside a system. Bare filenames are auto-dispatched (`hello.py` → `python3 hello.py`). One-shot mode: `l2 exec hello.py` (local file) creates a temp isolated system, executes, then destroys it. |
| `l2 list [name]`         | List systems or details |
| `l2 destroy <name>`      | Remove system and all objects |
| `l2 sel4-setup`          | One-shot seL4/Microkit dev environment |

Full surface: create, put, get, exec, list, destroy, status, revoke, sel4-setup. JSON output via `--json`.

## Verification (Smoke Test)

These commands should succeed with a v0.2.0 binary:

```bash
export L2_DATA_DIR=$(mktemp -d)
l2 create smoke --policy strict
l2 put smoke hello.txt --content 'hello from v0.2.0'
l2 get smoke hello.txt | grep -q 'v0.2.0'
l2 destroy smoke
echo "Smoke OK"
```

The CI runs an expanded version of this on every push to main.

## Status (v0.2.0)

See `STATUS.md` for the full current state.

**Core delivered:**
- Real Landlock + no_new_privs sandboxing for `--policy strict`
- Reliable CI with smoke tests
- All previous v0.1.0 functionality preserved and hardened

**Current focus (post v0.2.0):**
- Tighter sandboxing (seccomp, caps, user namespaces)
- Production seL4/Microkit integration

## Contributing & License

See `CONTRIBUTING.md`, `SECURITY.md`, and `docs/`.

This project is dual-licensed under **MIT OR Apache-2.0** (at your option).

- `LICENSE-MIT`
- `LICENSE-APACHE`

The SPDX identifier is `MIT OR Apache-2.0`.

---

**v0.1.0** remains available as an immutable historical baseline for evaluation and integrity checks against v0.2.0 and future releases.
