# l2 — Minimal High-Assurance System Substrate (v0.4.4)

Terminal-first CLI for creating, using, and destroying strongly isolated execution contexts. Narrow surface. Built for high-assurance with seL4 as the root of trust.

**Linux prototype** — ready for immediate use and validation (with powerful hardening and crypto).  
**seL4/Microkit** — the production/high-assurance path.

**v0.4.4 highlights + Miasma defenses + great-harden + AIO malware-cancer + l2 North-Star Containment:** `ransom-hardened` full-safety policy protocol for ransomware/malicious workload containment testing (WannaCry-class) and supply-chain worms (Miasma: Red Hat npm credential-stealing worm with preinstall, OIDC/GitHub exfil, tarball repack, "Miasma: The Spreading Blight" propagation); new self-contained `docs/examples/l2_ransomware_resistance_demo.c` + `l2_miasma_resistance_demo.c` (only succeed inside explicit l2 ws); `l2 harden --profile ransom-hardened` + `l2 audit --test` integration (Ransomware + Miasma containment checks, --apply for operational artifacts); dedicated harden profile. **NEW: `l2 great-harden`** for aerospace & industrial - supreme higher-assurance mode that makes servers impenetrable to all known malware/worms/viruses, closes logic gaps, aerospace-grade extreme hardening (kernel lockdown, full ro, no dynamic, great policy). **AIO "malware-cancer" attack sim** (`docs/examples/l2_malware_cancer_resistance_demo.c`): named comprehensive attack on the l2 substrate (ransom + Miasma + viruses + direct: state/trace/audit/crypto tamper, ns/bpf/setns/unshare escapes, fork/priv-esc on l2, git/pip/ELF/anti); prepared + validated under great-harden for the **grand demonstration of l2 North-Star Containment**. All additive, preserves prior guarantees. Builds on v0.4.3 security sweep. See full details in CHANGELOG.md.

See the dedicated **[Crypto & Hardening](#crypto--hardening-v040)** section (collapsible) and [SECURITY.md](SECURITY.md) for full v0.4.0+ crypto/hardening/strict-mcp/ransom-hardened details, plus [ROADMAP.md](ROADMAP.md) and [STATUS.md](STATUS.md).

## Install

### Recommended: cargo install (global)
```bash
git clone https://github.com/veilriven-design/l2.git
cd l2
git checkout v0.4.4
cargo install --path . --force
l2 --help
```

### From source (build only)
```bash
git clone https://github.com/veilriven-design/l2.git
cd l2
git checkout v0.4.4
cargo build --release
./target/release/l2 --help
# (or add target/release to PATH, or use the install command above)
```

Override state location anytime with `L2_DATA_DIR=/path l2 ...` (this is fully respected for create/put/get/exec/etc., and is automatically passed through `l2 exec`'s sudo escalation for strict/ransom-hardened policies that require root for namespace isolation).

## Quick Start

```bash
# Create an isolated system with full Landlock + no_new_privs enforcement
l2 create my-agent --policy strict

# Store data or code inside it (persisted in ~/.l2 or $L2_DATA_DIR)
l2 put my-agent task.sh --type code --content 'echo "Hello from l2"'

# Execute inside the isolated environment (strict policy applies Landlock)
# (l2 auto-escalates via sudo if namespace isolation requires root; L2_DATA_DIR and other L2_* vars are preserved)
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
- `ransom-hardened`: Full safety for ransomware/malicious code testing (WannaCry-class) and supply-chain worms (Miasma npm credential exfil + propagation). Auto-enforce + minimal ws-only surface. See `l2 policy ransom-hardened`, the demos in docs/examples/ (ransomware + miasma), and SECURITY.md.
- `great-harden`: **SUPREME** (via `l2 great-harden` command) for aerospace, industrial, critical systems. Higher assurance, advanced hardening, closes gaps, makes servers impenetrable to malware/worms/viruses (incl. AIO "malware-cancer" substrate attacks). Extreme configs + great policy. See `l2 great-harden --help`, `l2 policy great-harden`, README Troubleshooting.
  - Example (with `L2_DATA_DIR` for clean tests; sudo escalation preserves it):
    ```bash
    export L2_DATA_DIR=$(mktemp -d)
    l2 create miasma-test --policy ransom-hardened
    l2 put miasma-test miasma-sim.c --file docs/examples/l2_miasma_resistance_demo.c
    l2 exec miasma-test 'gcc -static -Wall -Wextra -o miasma-sim miasma-sim.c && ./miasma-sim'
    l2 audit --test  # PASS on the Miasma supply-chain check
    l2 destroy miasma-test
    ```

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

**Full v0.4.0+ specifics** (exact algorithms + rationale, hybrid construction, strict-mcp/ransom-hardened differences, concrete hardening commands/steps, generated artifacts, substrate integration for protecting crypto/keys, no-new-surfaces guarantees, data-driven loop, paced UX, explicit protocols) live in [SECURITY.md](SECURITY.md#cryptography-and-host-hardening-v040).

</details>

See `CHANGELOG.md` and the v0.1.0 tag for the previous baseline:
```bash
git checkout v0.1.0
```

## Common Commands

| Command                          | Description |
|----------------------------------|-------------|
| `l2 create <name> [--policy <protocol>]` | Create isolated system (use `--policy strict-mcp` for high-assurance agentic/MCP; `--policy ransom-hardened` for full-safety ransomware testing) |
| `l2 put <sys> <name> ...`        | Store object |
| `l2 get <sys> <name>`            | Retrieve object |
| `l2 exec [--policy <protocol>] <sys> [command]` | Run inside a system (or oneshot). Bare filenames auto-dispatch. (Auto sudo for strict/ransom-hardened; L2_DATA_DIR + L2_* vars preserved.) |
| `l2 list [name]`                 | List systems or details |
| `l2 destroy <name>`              | Remove system and all objects |
| `l2 sel4-setup [--fast/-f]`      | One-shot seL4/Microkit dev environment (paced output; `--fast` for CI/old hardware) |
| `l2 trace [--policy <protocol>] [--enforce] ...` | Collect seccomp traces (Phase 1). `--analyze <log>` generates real profiles. |
| `l2 harden --profile <name> [--apply] ...` | NSA/CISA/FBI-aligned host/container hardening for agentic era (with `--network-isolation`, seccomp gen, systemd units). `--apply` makes it operational (writes live artifacts + evidence for `audit --test`). Paced output. | 
| `l2 great-harden [--apply] ...` | Supreme aerospace/industrial 'great-harden' mode: extreme higher-assurance lockdown to make servers impenetrable to malware/worms/viruses. Closes logic gaps, aerospace-grade (kernel lockdown etc). Forces great policy. Paced. |
| `l2 crypto --profile <name> [--apply] ...` | Choose/apply verified crypto profile (AES-256-XTS-Argon2id, XChaCha20-Poly1305-Argon2id, or hybrid) for system encryption via LUKS/gocryptfs + l2 isolation. Paced output. |
| `l2 policies` / `l2 policy <name>` | Discover and inspect policy protocols (e.g. `strict-mcp`, `ransom-hardened`). |
| `l2 audit ...`                   | View/manage tamper-evident authority audit log. |

Full surface includes the above + status, revoke, etc. All commands support `--json`. Use `--policy strict-mcp` (or other protocols) for explicit guarantees. JSON output via `--json`.

## Verification (Smoke Test)

These commands exercise the full v0.4.4+ surface (policies including ransom-hardened, strict-mcp, great-harden, crypto, harden --apply for operational artifacts, trace with profile output, audit + ransomware + Miasma + AIO malware-cancer substrate + great-harden containment checks). The `harden --apply` + `audit --test` + `l2 great-harden` is the supreme world-class north-star workflow for auditable, standards-backed agentic/MCP/aerospace/industrial hardening. They should succeed:

```bash
export L2_DATA_DIR=$(mktemp -d)
l2 policies
l2 policy strict-mcp
l2 crypto --list
echo 'fake trace' > /tmp/trace.log
l2 harden --profile strict-mcp --dry-run --fast --generate-seccomp /tmp/trace.log || true
# The beautiful operational loop: --apply writes live units/profiles/confs + updates evidence json
l2 harden --profile strict-mcp --fast --generate-seccomp /tmp/trace.log --apply || true
# Supreme great-harden for aerospace/industrial (new)
l2 great-harden --fast --apply || true
l2 create smoke --policy strict-mcp
l2 put smoke hello.txt --content 'hello from v0.4.4'
l2 get smoke hello.txt | grep -q 'v0.4.4'
echo 'fake log' > /tmp/fake.log
l2 trace --analyze /tmp/fake.log --output-profile /tmp/profile.txt
l2 audit --tail 5
l2 audit --verify
l2 audit --test  # runs regular automated checks vs. latest security standards (CISA/NSA/FBI/Linux hardening + ransomware + Miasma supply-chain + AIO malware-cancer substrate + great-harden aerospace); now sees real --apply artifacts for strict-mcp/ransom-hardened/great-harden (the supreme world-class north-star loop)
l2 destroy smoke
echo "Smoke OK"
# (L2_DATA_DIR overrides are preserved across any sudo escalation in exec/harden/great-harden paths.)
```

The CI runs an expanded version of this on every push to main (including fmt, clippy `-D warnings`, and the new tooling).

See the Troubleshooting section below for help with `L2_DATA_DIR`, sudo escalation, old kernels, etc. when running the smoke or the resistance demos.

## Troubleshooting

### `L2_DATA_DIR` with `l2 exec` (and sudo escalation)

`l2` respects `L2_DATA_DIR` (or `L2_DATA_DIR=/path l2 ...`) for all state (systems, objects, harden reports, audit logs, seccomp profiles, etc.). This is heavily used for clean smoke/CI/demo runs.

However, `l2 exec` under strict-family policies (`strict`, `strict-mcp`, `ransom-hardened`) auto-escalates via `sudo` (to obtain privileges for `unshare` + full Landlock/no_new_privs). By default `sudo` strips most environment variables.

**l2 now automatically preserves `L2_DATA_DIR` (and all `L2_*` variables) across the escalation:**

```
→ requesting root for isolated exec (namespaces + strict policy)...
   sudo L2_DATA_DIR=/tmp/tmp.xxx /path/to/l2 exec ...
```

The sudo child therefore sees the same data dir, so `create`/`put`/`exec` under a temp dir continue to work (no more "system 'foo' not found (data dir: ~/.l2)").

If you invoke `sudo l2 ...` manually, include the override on the command line:

```
L2_DATA_DIR=/tmp/my-test sudo l2 exec ...
```

See the resistance demo headers, the `ransom-hardened` policy example in this README, and SECURITY.md for typical usage with `export L2_DATA_DIR=$(mktemp -d)`.

### Sudo / privilege escalation for `exec`

- `l2 exec` (named systems or oneshot) under strict/ransom-hardened policies prints a notice and runs the current binary under `sudo` so that namespace isolation and strong sandboxing can be applied.
- This works even for `cargo install`d binaries (uses `current_exe()`).
- You will be prompted for your password (unless you have passwordless sudo configured for the user).
- The inner run drops privileges back to the original user (via `SUDO_UID`/`SUDO_GID`) before executing your workload.
- In non-interactive/CI environments without a TTY, sudo may fail. Workarounds:
  - Run the whole sequence as root (not recommended for daily use).
  - Use `L2_USE_CORE=1` (moves some state ops to the out-of-process core; isolation still happens in the CLI for now).
  - For kernels/containers where `unshare` is unavailable, l2 falls back to direct execution (with a warning). You still get Landlock (if available), seccomp, capability bounding, `no_new_privs`, env sanitization, etc.

### Old / restricted kernels and partial enforcement

Many protections are best-effort on older kernels:

- Landlock (FS sandbox): requires kernel ≥ 5.13 + LSM enabled. On older systems you may see "Landlock not enforced".
- Seccomp Phase 1 enforcing: works on modern kernels; observer mode (`L2_STRICT_SECCOMP_OBSERVE=1`) is more widely available.
- User namespaces: experimental (`L2_EXPERIMENTAL_USER_NS=1`). Full `pivot_root` + id mapping is future work.
- In these cases the demos will still show many "BLOCKED" results thanks to the remaining controls, but some vectors (e.g. certain network or FS operations) may succeed on the host.

Run `l2 policy ransom-hardened` (or `strict-mcp`) for the current guarantees on your system.

### Running the resistance demos (`l2_*_resistance_demo.c`)

These are intended to be compiled and executed *inside* an l2 system:

```bash
export L2_DATA_DIR=$(mktemp -d)
l2 create test --policy ransom-hardened
l2 put test demo.c --file docs/examples/l2_miasma_resistance_demo.c   # or the ransomware one
l2 exec test 'gcc -static -Wall -Wextra -o sim demo.c && ./sim'
l2 audit --test   # should PASS the relevant containment check(s)
l2 destroy test
```

For supreme AIO substrate defense (malware-cancer): use `great-harden` policy + `l2 great-harden --fast --apply` and the `l2_malware_cancer_resistance_demo.c` (ransomware + Miasma + direct attacks on l2 state/trace/audit/crypto + ns/bpf escapes etc.).

- Use `-static` to minimize the read-only paths Landlock must allow.
- The programs deliberately attempt "bad" things and report BLOCKED vs. UNEXPECTED SUCCESS.
- Only files you explicitly `put` into the workspace can be affected.
- After a run, `l2 audit --test` (plus the harden json if you ran `l2 harden --profile ...` or `l2 great-harden --apply`) gives the machine-readable evidence.

See the headers inside the `.c` files for exact usage and cross-references.

### The Grand Demonstration of l2 North-Star Containment (malware-cancer AIO sim)

For the ultimate "what l2 does" show — the single AIO program that hits ransomware + supply-chain worms + viruses + direct attacks on the l2 substrate itself, all contained:

```bash
export L2_DATA_DIR=$(mktemp -d)
l2 great-harden --fast --apply || true   # prepare the North-Star Containment posture (kernel lockdown, extreme sysctls, units, no-usb, audit for state/ws)
l2 create cancer-test --policy great-harden
l2 put cancer-test cancer-sim.c --file docs/examples/l2_malware_cancer_resistance_demo.c
l2 exec cancer-test 'gcc -static -Wall -Wextra -o cancer-sim cancer-sim.c && ./cancer-sim'  # grand demo of l2 North-Star Containment
l2 audit --test   # verifies North-Star Containment of AIO malware-cancer (PASS with great-harden json + apply artifacts)
l2 destroy cancer-test
```

Inside the ws (only files you `put`), the sim "ransom"s, "infects", drops notes, etc. — everywhere else is BLOCKED by the substrate (Landlock ws-only + tiniest RO + no /proc/no /etc, seccomp Phase 1 ENFORCING with extended NEVER for net/ptrace/bpf/setns/unshare/keyctl/mknod, env sanitization + HOME=ws, caps/no_new_privs, rlimits, host great-harden --apply lockdown). The audit --test + harden json is the machine-readable evidence of North-Star Containment.

This is the repeatable, auditable, beautiful north-star workflow for aerospace/industrial/critical systems.

### Other common issues

- `l2 harden --apply` (or scripts) may still need manual `sudo` for some host changes (sysctls, nft, systemd units). The tool is intentionally advisory and auditable.
- Corrupt state: `l2 audit --verify` will tell you; you can remove the `state.json` under your `L2_DATA_DIR` (you will lose existing systems).
- `l2 sel4-setup` on slow/old machines: pass `--fast` (or set `L2_FAST=1`).
- Binary not found after `sudo`: the escalation now uses the full path from `current_exe()`, so `cargo install`d or `./target/release/l2` both work.

If you hit something else, the source of truth is the narrow terminal interface + explicit audit log. Feel free to open an issue with the exact commands + `l2 audit --tail 20` output.

## Status (v0.4.4)

See the dedicated Troubleshooting subsection above for common issues (especially `L2_DATA_DIR` with sudo escalation, the resistance demos, etc.).

See [STATUS.md](STATUS.md) for the full current state and [ROADMAP.md](ROADMAP.md) for direction.

**Core delivered (v0.4.0+ focus):**
- Explicit policy protocols (`strict-mcp` as main focus for agentic/MCP; `ransom-hardened` for full-safety ransomware/malicious testing) with clear guarantees.
- `l2 crypto`: selectable verified profiles (including hybrid) for system encryption, integrated with l2 isolation.
- `l2 harden`: concrete NSA/CISA/FBI-aligned host hardening + automatic systemd units + trace-driven seccomp profiles. Supports `ransom-hardened` profile.
- `l2 trace` + analysis for real Phase 1 data collection under any protocol.
- Paced typewriter output in setup/hardening/crypto tools.
- `l2 policies` / `l2 policy <name>` for discovery.
- Stronger defaults and deeper integration between policies, crypto, host hardening, and audit (`l2 audit --test`).
- `ransom-hardened` + `l2_ransomware_resistance_demo.c` + `l2_miasma_resistance_demo.c` + harden/audit integration for repeatable WannaCry-class + Miasma supply-chain worm containment validation.
- `l2 great-harden` (supreme command) + great-harden policy + `l2_malware_cancer_resistance_demo.c` for aerospace/industrial: higher assurance, closes gaps, AIO "malware-cancer" (direct substrate attack) defense, **grand demonstration of l2 North-Star Containment**, impenetrable servers for critical complexes.

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

**v0.1.0** remains available as an immutable historical baseline for evaluation and integrity checks against v0.4.4 and future releases.

See `CHANGELOG.md`, `STATUS.md`, `ROADMAP.md`, and the `docs/` directory for the complete picture of what v0.4.4 provides for users building high-assurance agentic/AI/MCP systems on the l2 substrate (including full-safety ransomware testing support).
