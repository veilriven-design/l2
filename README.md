# l2 — Minimal High-Assurance System Substrate (v0.4.0)

Terminal-first CLI for creating, using, and destroying strongly isolated execution contexts. Narrow surface. Built for high-assurance with seL4 as the root of trust.

**Linux prototype** — ready for immediate use and validation (with powerful hardening and crypto).  
**seL4/Microkit** — the production/high-assurance path.

**v0.4.0 highlights for users:** explicit policy protocols (especially `strict-mcp`), `l2 crypto` (verified profiles + hybrid for system encryption), `l2 harden` (NSA/CISA/FBI host prep), `l2 trace` (policy-aware seccomp collection + profile generation), and paced "typewriter" guidance in setup tools.

See the dedicated **[Crypto & Hardening](#crypto--hardening-v040)** section (collapsible) and [SECURITY.md](SECURITY.md) for full v0.4.0 crypto/hardening/strict-mcp details, plus [ROADMAP.md](ROADMAP.md) and [STATUS.md](STATUS.md).

## Install

### Recommended: cargo install (global)
```bash
git clone https://github.com/veilriven-design/l2.git
cd l2
git checkout v0.4.0
cargo install --path . --force
l2 --help
```

### From source (build only)
```bash
git clone https://github.com/veilriven-design/l2.git
cd l2
git checkout v0.4.0
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
# On very old/slow machines, you can disable the slow "typing" output:
# l2 sel4-setup --fast
cat ~/l2-sel4-workspace/README-l2-sel4.md
```

<a id="crypto--hardening-v040"></a>
## Crypto & Hardening (v0.4.0+)

Dedicated tooling and explicit policy protocols (`strict-mcp` main focus) for high-assurance agentic/AI/MCP systems. NSA/CISA-aligned host prep, verified crypto for system encryption, and data-driven seccomp policies — all integrated with the l2 substrate. Long guidance uses paced "typewriter" output.

<details>
<summary><strong>Read more (l2 crypto profiles + hybrid, l2 harden, strict-mcp divergence, trace-to-profile pipeline, integration)</strong></summary>

**Policy protocols** (explicit; discover and inspect):

```bash
l2 policies
l2 policy strict-mcp
```

- `strict`: Strong baseline (Landlock + no_new_privs + seccomp).
- `strict-mcp`: Current flagship — stricter defaults for agentic/MCP/tool workloads (seccomp enforcing auto-on, tighter Landlock). Pair with `l2 harden --profile strict-mcp`.

Use with `--policy strict-mcp` on create/exec/trace/etc.

### `l2 crypto` — Verified Profiles for System Encryption

```bash
l2 crypto --list
l2 crypto --profile hybrid-aes-chacha --apply --network-isolation
```

Only battle-tested, verified open-source algos (AES-256-XTS NIST, XChaCha20-Poly1305 IETF, Argon2id PHC). Hybrid mixes complementary designs for defense-in-depth. Applies proficiently via LUKS2/gocryptfs; `--apply` is confirmed + paced; generates units; keys protected via `l2 exec --policy strict-mcp`.

### `l2 harden` — Concrete Host Hardening

```bash
l2 harden --profile strict-mcp --target host --network-isolation --generate-seccomp trace.log
```

NSA/CISA/FBI-aligned steps (dedicated users, sysctls, audit, caps drop, ns restrictions, Protect*). Produces reports, full hardened systemd units, and real seccomp profiles from traces. `--network-isolation` for default-deny outbound on agents.

### Trace-Driven Policies

```bash
l2 trace --policy strict-mcp ./workload --analyze trace.log
```

Collects under chosen policy; `--analyze` produces minimal allowlists loadable by enforcing filter or systemd `SystemCallFilter`.

**Full v0.4.0 specifics** (exact algorithms + rationale, hybrid construction, strict-mcp differences, concrete hardening commands/steps, generated artifacts, substrate integration for protecting crypto/keys, no-new-surfaces guarantees, data-driven loop, paced UX, explicit protocols) live in [SECURITY.md](SECURITY.md#cryptography-and-host-hardening-v040).

</details>

See `CHANGELOG.md` and the v0.1.0 tag for the previous baseline:
```bash
git checkout v0.1.0
```

## Common Commands

| Command                          | Description |
|----------------------------------|-------------|
| `l2 create <name> [--policy <protocol>]` | Create isolated system (use `--policy strict-mcp` for high-assurance agentic/MCP) |
| `l2 put <sys> <name> ...`        | Store object |
| `l2 get <sys> <name>`            | Retrieve object |
| `l2 exec [--policy <protocol>] <sys> [command]` | Run inside a system (or oneshot). Bare filenames auto-dispatch. |
| `l2 list [name]`                 | List systems or details |
| `l2 destroy <name>`              | Remove system and all objects |
| `l2 sel4-setup [--fast/-f]`      | One-shot seL4/Microkit dev environment (paced output; `--fast` for CI/old hardware) |
| `l2 trace [--policy <protocol>] [--enforce] ...` | Collect seccomp traces (Phase 1). `--analyze <log>` generates real profiles. |
| `l2 harden --profile <name> ...` | NSA/CISA/FBI-aligned host/container hardening for agentic era (with `--network-isolation`, seccomp gen, systemd units). Paced output. |
| `l2 crypto --profile <name> [--apply] ...` | Choose/apply verified crypto profile (AES-256-XTS-Argon2id, XChaCha20-Poly1305-Argon2id, or hybrid) for system encryption via LUKS/gocryptfs + l2 isolation. Paced output. |
| `l2 policies` / `l2 policy <name>` | Discover and inspect policy protocols (e.g. `strict-mcp`). |
| `l2 audit ...`                   | View/manage tamper-evident authority audit log. |

Full surface includes the above + status, revoke, etc. All commands support `--json`. Use `--policy strict-mcp` (or other protocols) for explicit guarantees. JSON output via `--json`.

## Verification (Smoke Test)

These commands should succeed with a v0.4.0 binary (expanded for policies, crypto, harden, trace):

```bash
export L2_DATA_DIR=$(mktemp -d)
l2 create smoke --policy strict-mcp
l2 put smoke hello.txt --content 'hello from v0.4.0'
l2 get smoke hello.txt | grep -q 'v0.4.0'
l2 trace --policy strict-mcp --analyze /dev/null || true   # (trace tooling)
l2 harden --profile strict-mcp --dry-run --fast || true
l2 crypto --list
l2 policies
l2 destroy smoke
echo "Smoke OK"
```

The CI runs an expanded version of this on every push to main (including fmt, clippy `-D warnings`, and the new tooling).

## Status (v0.4.0)

See [STATUS.md](STATUS.md) for the full current state and [ROADMAP.md](ROADMAP.md) for direction.

**Core delivered (v0.4.0 focus):**
- Explicit policy protocols (`strict-mcp` as main focus for agentic/MCP) with clear guarantees.
- `l2 crypto`: selectable verified profiles (including hybrid) for system encryption, integrated with l2 isolation.
- `l2 harden`: concrete NSA/CISA/FBI-aligned host hardening + automatic systemd units + trace-driven seccomp profiles.
- `l2 trace` + analysis for real Phase 1 data collection under any protocol.
- Paced typewriter output in setup/hardening/crypto tools.
- `l2 policies` / `l2 policy <name>` for discovery.
- Stronger defaults and deeper integration between policies, crypto, and host hardening.

**Ongoing:**
- Production seL4/Microkit integration (l2-core as protection domain).
- Further per-protocol divergence and automated hardening in `l2 harden`.

## Contributing & License

See `CONTRIBUTING.md`, `SECURITY.md`, and `docs/`.

This project is dual-licensed under **MIT OR Apache-2.0** (at your option).

- `LICENSE-MIT`
- `LICENSE-APACHE`

The SPDX identifier is `MIT OR Apache-2.0`.

---

**v0.1.0** remains available as an immutable historical baseline for evaluation and integrity checks against v0.4.0 and future releases.

See `CHANGELOG.md`, `STATUS.md`, `ROADMAP.md`, and the `docs/` directory for the complete picture of what v0.4.0 provides for users building high-assurance agentic/AI/MCP systems on the l2 substrate.
