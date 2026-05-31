# l2 — Minimal High-Assurance System Substrate (v0.2.0)

Terminal-first CLI for creating, using, and destroying strongly isolated execution contexts. Narrow surface. Built for high-assurance with seL4 as the root of trust.

**Linux prototype** — ready for immediate use and validation.  
**seL4/Microkit** — the production/high-assurance path.

## Install

### Recommended: cargo install (global)
```bash
git clone https://github.com/veilriven-design/l2.git
cd l2
git checkout v0.2.0
cargo install --path . --force
l2 --help
```

### From source (build only)
```bash
git clone https://github.com/veilriven-design/l2.git
cd l2
git checkout v0.2.0
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
l2 put my-agent task.rs --type code --content 'fn main() { println!("Hello from l2"); }'

# Execute inside the isolated environment (strict policy applies Landlock)
l2 exec my-agent ./task

l2 destroy my-agent
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
| `l2 exec <sys> '<command>'` | Run command inside (strict = Landlock enforced) |
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

MIT + Apache-2.0 (dual).

---

**v0.1.0** remains available as an immutable historical baseline for evaluation and integrity checks against v0.2.0 and future releases.
