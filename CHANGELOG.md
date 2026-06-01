# Changelog

## [0.3.9] - 2026-06-02

### Added
- **`l2 harden`** — New major command (and `scripts/harden.sh`) for applying high-assurance, NSA/CISA/FBI-aligned hardening to hosts/containers for the agentic/AI/MCP era. Supports profiles (especially `strict-mcp`), `--network-isolation`, `--generate-seccomp <trace>`, and produces rich reports + full hardened systemd unit templates.
- **Real seccomp profile generation** from traces collected via `l2 trace --policy strict-mcp`. The custom Phase 1 enforcing filter can now directly load these generated minimal profiles (via `L2_SECCOMP_PROFILE`).
- **`l2 policies`** and **`l2 policy <name>`** commands to discover and inspect available policy protocols (with excellent detail for `strict-mcp`).
- `strict-mcp` as a first-class, diverging policy protocol (stronger defaults than `strict`, including automatic Phase 1 enforcing).
- Concrete, actionable host hardening steps in the harden script (dedicated agent users, kernel sysctls, audit rules, capability bounding, namespace restrictions, etc.).
- `--network-isolation` flag and guidance in `l2 harden`.
- Automatic generation of production-ready hardened systemd unit templates when using `strict-mcp`.

### Changed
- `apply_strict_sandbox` is now policy-aware. `strict-mcp` applies a more conservative Landlock posture.
- `normalize_policy` returns richer metadata and treats `strict-mcp` specially.
- `l2 trace --policy strict-mcp` now enables the enforcing filter by default.
- The enforcing seccomp filter supports loading external trace-derived profiles and has stronger safety checks (NEVER_ALLOWED blacklist, size limits, etc.).
- All relevant documentation (ROADMAP, STATUS, allowlist doc, harden reports) updated to reflect the new focus on `strict-mcp` + host hardening.
- Bumped crate version to 0.3.9.

This release significantly advances l2's mission as a high-assurance substrate for the agentic era. The combination of `l2 harden` + `strict-mcp` + trace-driven seccomp profiles provides a practical path toward NSA/CISA-grade controls for MCP and autonomous agent workloads.

## [0.3.2] - 2026-06-02

### Added
- **`l2 sel4-setup` paced / "typewriter" output**: The script now reveals its terminal output slowly and methodically (character-by-character for headings, line-by-line for long instruction blocks) so users can comfortably read along instead of receiving a massive wall of text instantly. This is especially valuable for the large RHEL+Podman hardware warning block.
- **`--fast` / `-f` flag** for `l2 sel4-setup`: Disables all slow/paced output for instant behavior (also works via `L2_FAST=1` or `L2_SEL4_SETUP_FAST=1`, and when invoking the script directly). Ideal for old hardware, scripts, or CI.
- The shell script now accepts `--fast` / `-f` as a command-line argument and forwards it cleanly whether called via the `l2` binary or directly.

### Changed
- Updated all version references, documentation, and the generated workspace README to document the new pacing behavior and fast-escape options.
- Bumped crate version to 0.3.2.

This is a small but high-quality UX polish on top of the v0.3.1 sel4-setup improvements, making the on-ramp significantly more pleasant on a wide range of hardware.

## [0.3.1] - 2026-06-02

### Changed
- **`l2 sel4-setup` UX hardening for real-world RHEL + Podman users on low-end and ancient hardware** (the main deliverable of this point release):
  - The Microkit SDK tarball path is now the unambiguous, strongly recommended default for almost everyone. It is downloaded early and presented with clear "extract and go" instructions before any optional heavy steps.
  - On RHEL-family + podman systems the previous near-default offer (`[Y/n]`) of the full official seL4-CAmkES-L4v container has been removed.
  - Replaced with a large, explicit warning block that states realistic wall-clock times by hardware class:
    - Modern machines: several hours
    - 2015-2018 hardware: 8-20+ hours common
    - Ancient/low-RAM machines (X200-class ThinkPads, early 2010s EliteBooks, ≤8 GB RAM, mechanical disks): 15-40+ hours or more is realistic due to rootless Podman + fuse-overlayfs layer I/O.
  - The full container (which pulls 10-50+ GB of images and runs `make user` from the official dockerfiles) now requires the user to type the exact phrase `yes i accept the long build time`. Empty input or any other reply safely skips it.
  - Added explicit "alternate route" language and host-package guidance so users on old hardware can get a working cross-compiler + Microkit environment in minutes instead of days.
  - The generated `~/l2-sel4-workspace/README-l2-sel4.md` was updated with the same stronger guidance and hardware-aware recommendations.
- This change keeps the full container path fully available for users who genuinely need CAmkES + L4v/Isabelle, while making the common l2 + Microkit case fast and safe even on 15-year-old RHEL machines.

### Fixed
- Minor: the previous prompt defaulted to "yes" on empty input, which was too aggressive for a multi-hour-to-multi-day operation on vintage hardware.

Bumped crate version to 0.3.1.

## [0.3.0] - 2026-06-01

### Added
- **Audit logging and `l2 audit` subcommand**: Full append-only JSONL authority audit log (`audit.log`) for create/put/exec/destroy/revoke/escalate/sandbox events. New `l2 audit [--tail N] [--json] [--path]` for inspection. Directly fulfills SECURITY.md "Evidence and audit" requirement.
- **Architecture prep for core split**: 
  - New `src/lib.rs` extracting core types (`Substrate`, `System`, `Object`) and helpers (persistence, workspace prep, `L2Core` trait) for clear boundary between CLI and future out-of-process / C core.
  - `host/core.rs` (l2-core binary) now implements real L2P handling (ping, status, create, list) using the shared library Substrate (in-memory simulation today).
- **Deeper correctness & robustness gaps closed** (continued from v0.2.x):
  - `data_dir()` / `load_state()` / `save_state()` now return proper `Result` (no more HOME panics).
  - `load_state()` warns on corrupt state instead of silent fallback.
  - New `warn_on_cleanup_err` helper (in lib) replaces many silent `let _ =` cleanups in oneshot/exec/prepare paths with visible warnings.
  - JSON output paths (`print_json`, `json_line`) no longer panic on serialization failure (graceful fallback).
  - Many other small robustness fixes and 5+ new tests (state roundtrips, corrupt JSON, data_dir override, audit path, warn helper, isolation helpers). Test count now 17+.
- **CI improvements**: `cargo-audit` security scanning step added to GitHub Actions + expanded smoke tests (now exercises `l2 audit` subcommand).

### Changed
- Significant reduction in code duplication between CLI and core logic via library extraction (major step toward the narrow L2P + out-of-process core architecture described in docs/PROTOCOL.md and original analysis).
- `l2-core` binary is now a functional (if still simulated) L2P participant using the shared core.
- Updated STATUS.md, README quickstart references, and internal comments to reflect v0.3.0 state and split progress.
- Bumped to 0.3.0.

### Fixed
- Various silent failure modes in cleanup and state paths now produce warnings.
- Remaining dangerous `.unwrap()` / `.expect()` in main hot paths either removed or given clear messages (tests excluded).
- Minor issues in object path handling and oneshot error recovery paths.

This release focuses on **correctness, auditability, and architecture foundation** while preserving the project's minimal high-assurance philosophy. The Linux prototype is stronger; the seL4 path remains the long-term target.

See the full analysis follow-up and plan in the repo history / docs for context.

## [0.2.1] - 2026-06-01

### Fixed
- **Privilege escalation for `l2 exec`**: Automatically re-invokes the current `l2` binary under `sudo` (using `std::env::current_exe()`) when namespace isolation (`unshare`) requires root. This fixes the broken workflow for users who installed via `cargo install` (binary in `~/.cargo/bin`, not in root's `PATH`):
  - `sudo l2 ...` now works (no more "command not found").
  - No more needing to type awkward `sudo ./target/release/l2 ...` after source builds.
  - The original user's `~/.l2` state is still used thanks to existing `SUDO_USER` handling.
- Updated the outdated error hint that suggested `./target/release/l2` paths.
- **Much better diagnostics for bad exec targets** + major UX improvements for code execution:
  - `l2 exec my-agent ./nonexistent` ... (previous improvements)
  - New convenient forms: bare-name auto-dispatch inside systems (`l2 exec mysys hello.py` → `python3 hello.py`) and full **one-shot mode** (`l2 exec hello.py` from local file creates a temporary isolated system, runs it under the requested policy, then destroys it completely).
  - Shebang (`#!`) is now the primary extensibility mechanism for "any language on the host".
  - Expanded dispatch table (Python, shell, Ruby, Perl, Node, Lua, PHP, Go single-file).
  - Nicer colored output for dispatch, oneshot lifecycle, and policy-related interpreter errors.
  - `--policy` supported on `exec` (especially useful for oneshot / MCP workloads).
- **Documentation**: Fixed Quick Start example (previously put `task.rs` then exec'd non-existent `./task`; now uses `task.sh` invoked via `sh task.sh`, which actually works inside the materialized workspace under Landlock).
- Bumped crate version to 0.2.1.

### Changed
- `l2 exec` now proactively escalates for isolation guarantees (consistent with the documented requirement for full namespaces on typical Linux kernels). The inner invocation under sudo produces the same output and side-effects.

## [0.2.0] - 2026-05-31

### Added / Hardening
- **Real Landlock FS sandbox for `--policy strict`**: full R/W/X confined to the system workspace, RO+EXEC on curated system paths (e.g. /bin, /proc, /dev). Writes outside the workspace are now denied by the kernel LSM. (The core deliverable of this release.)
- CI (GitHub Actions) on push to main + v0.2.0-development: build, test, clippy -D warnings, fmt --check, plus smoke tests exercising strict policy + Landlock.
- Smoke tests in CI that create systems with `--policy strict`, exercise put/get, and invoke the exec + sandbox path (tolerant of runner privilege limits for unshare while validating the hardening).

### Changed
- Bumped crate version to 0.2.0 (v0.1.0 remains the tagged base for integrity/eval history).
- Removed hallucinated duplicate `l2/` subdirectory that had crept into working trees.
- Formatting cleanup across src/ (cargo fmt enforced in CI).
- sandbox.rs now actually implements the previously stubbed "Landlock hooks" with correct landlock 0.4.5 API usage.
- Multiple iterations on CI smoke tests until main checks are reliably green.

## [0.1.0] - 2026-05-31

### Added
- Terminal-first CLI with full narrow interface (create, put, get, exec, list, destroy, etc.)
- Linux prototype with namespaces + Landlock + no_new_privs sandboxing
- Disciplined C core (`l2_sys_*` interface) with memory safety guards
- Out-of-process L2P protocol support
- Full seL4/Microkit integration on-ramp with `l2 sel4-setup` and buildable example
- High-assurance documentation and C coding guidelines
- Explicit prototype warnings and production seL4 path

### Changed
- Extreme scope restraint maintained throughout
- Total cleanup and explicit authority model enforced

l2 is now ready for high-assurance use cases with seL4 as the foundation.
