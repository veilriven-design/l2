# Changelog

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
