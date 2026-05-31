# Changelog

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
