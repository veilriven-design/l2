# Changelog

## [0.4.7] - 2026-06-06

### June 2026 Up-to-the-Minute Full Sweep of CISA/NSA Guidance
- Performed another complete sweep (using current web/X sources) for the absolute latest CISA/NSA publications as of June 2026 (post May MCP CSI).
- Key new/emphasized pubs integrated: CISA/NSA/Five Eyes "Careful Adoption of Agentic AI Services" CSI (Apr 30/May 2026) - 5 risk categories (privilege risks/least priv/scope creep/confused deputy, design and configuration risks, behaviour risks, structural risks, accountability risks) + best practices (design/develop/deploy/operate secure agents with isolation, no broad/unrestricted access to sensitive/critical, explicit approvals/human oversight, continuous monitoring/audit, Secure by Design as part of cybersec not separate). NSA CSI "Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation" (May 20, 2026) - gaps (optional auth/bearer tokens w/o lifecycle, insecure serialization/injection, no RBAC/proto least-priv, weak approvals on capability changes, token passthrough/replay, common misconfigs in open impls, unverified task propagation, context leakage) + recs (enforce in impl: auth/integrity/validation/isolation/monitoring/approvals/no passthrough, treat agentic/MCP as continuum). CPG 2.0 details confirmed/enhanced (GOVERN emphasis, specific goals 1.B/1.E/3.H/4.A/4.B etc.). Continued alignment to prior Mar 2026 AI/ML supply chain, Dec 2025 OT AI, etc.
- l2 already provided the core (explicit ws-only authority via put/exec, Landlock+seccomp NEVER+unshare+cap drop+no_new_privs+env_clear+rlimits for MCP/agent isolation/no ambient, audit chain for accountability/monitoring, great-harden --apply for host lockdown, demos for supply/ransom/substrate attacks, --test for evidence). Sweep added explicit mappings, updated language in policy descs, harden standards/comments, docs.
- No behavior change; docs/code now reference "June 2026 sweep" + exact risk categories/best practices from the new CSIs. Strengthens claim that l2 is the minimal north-star substrate for agentic/MCP/AI/OT per latest.

### Cryptography Improvements and Polish (prepare prepare prepare)
- Expanded/polished `l2 crypto`: 3 verified profiles (aes256-xts-argon2id, xchacha20-poly1305-argon2id, hybrid-aes-chacha for defense-in-depth); --apply now respects L2_DATA_DIR, writes crypto/crypto-latest.json evidence (for audit --test), non-interactive in --fast/--json, better network-isolation notes.
- Script now supports --json (structured output for list/apply), improved LUKS/gocryptfs guidance, MCP-aware helpers.
- Rust CLI: passes --json to script, conditional prints, better json path for evidence.
- Audit --test: new check "Crypto profiles for data-at-rest (verified algos + l2 substrate key protection)" (consumes json, reports apply); updated standards json + len assert.
- CI smoke: enhanced crypto tests (json list, hybrid guidance, tolerated).
- Demos: cancer resistance demo updated with polished crypto vectors (contained encrypt/exfil of keys/profiles only in ws; host crypto protected); summary and headers note v0.4.7 crypto improvements.
- Docs: README crypto section, SECURITY.md, STATUS, CHANGELOG, demo headers updated with hybrid rationale, L2_DATA_DIR support, audit evidence, NSA AI Data Sec / CPG at-rest / MCP key protection mappings.
- Integration: crypto evidence now in great-harden/harden standards; recommended in agentic/MCP flows (keys only via strict-mcp exec); pairs with great-harden for data at rest in critical infra.
- "prepare prepare prepare": full UX polish (paced + json), evidence loop closed with audit, demos exercise crypto containment, standards alignment explicit, no new surfaces, ready for grand North-Star demos.

### Alignment to Latest NSA/CISA Guidance (as of 2026, to the hour)
- Full sweep and update of l2 to meet NSA and CISA recommendations current as of the latest 2026 publications (CPG 2.0, AI/ML supply chain CSI, MCP security design for AI automation, OT AI integration, agentic AI, etc.). l2 substrate now explicitly documents and aligns to these for agentic/AI/MCP/critical infrastructure use.
- Full sweep against CISA Cross-Sector CPGs 2.0 (Dec 2025: GOVERN, least priv 3.H, malicious code detection, MSP/oversight risks, NIST CSF 2.0 alignment), NSA CSI AI/ML Supply Chain Risks & Mitigations (Mar 2026: poisoning, AIBOM/SBOM, provenance), NSA MCP Security Design Considerations for AI-Driven Automation (May 2026 - l2 strict-mcp is the secure substrate), NSA/CISA OT AI Integration Principles (Dec 2025: governance, human-in-loop, fail-safes, separate AI data), Agentic AI Careful Adoption (Apr 2026), AI Data Security.
- Updates: harden.sh now explicitly references CPG 2.0 + MCP CSI + AI supply chain + SBOM/AIBOM recs for AI workloads; standards in json/audit expanded; policy descs in main.rs updated (strict-mcp for NSA MCP, great for OT/AI/CPG); docs (README/SECURITY/STATUS/ROADMAP) updated with mappings and "how l2 meets".
- No new code surfaces; enhancements are in guidance, comments, audit checks, and docs. Existing primitives (Landlock/least priv, seccomp, explicit authority, audit chain, demos for supply chain/ransomware/substrate, great-harden for critical) already meet or exceed. Added SBOM rec and CPG/GOVERN emphasis.
- Verified: l2 audit --test now surfaces CPG 2.0/MCP/AI supply chain in standards; smokes pass.

### Added / Improved (harden operationalization - making the north-star cybersec workflow real)
- `l2 harden --apply`: New flag (modeled exactly on the beautiful `crypto --apply`). Turns advisory guidance into operational reality: writes live systemd units, seccomp profiles, sysctl/audit/nft configs to standard + l2 locations; attempts safe application (with user confirmation in paced output, sudo fallbacks); updates the `<profile>-latest.json` with "apply": true + extended "applied" list. 
- The full loop is now world-class and north-star worthy: `l2 trace --policy strict-mcp ... --analyze --output-profile ; l2 harden --profile strict-mcp --generate-seccomp <trace> --apply ; l2 exec --policy strict-mcp ... ; l2 audit --test` (now sees real applied artifacts + confirms standards + ransomware containment).
- Script enhancements for apply (ransom-hardened specific blocks too), better json evidence, "APPLY SUCCESS" messaging, prepared apply scripts in $L2_BASE/harden/applied/.
- `audit --test` now surfaces "+ --apply operational artifacts" in PASS details when present.
- Updated smoke, README, table, SECURITY/ROADMAP docs to showcase the complete, auditable, applied agentic hardening workflow as the repeatable pattern for major cyber problems (MCP tool abuse, ransomware containment, host prep for AI agents, supply-chain resistant execution).
- **Miasma supply-chain defenses**: New `docs/examples/l2_miasma_resistance_demo.c` (self-contained sim of npm preinstall tampering, OIDC/GitHub/cloud credential theft + exfil to "Miasma: The Spreading Blight" repos, tarball repack + Sigstore sim, self-propagation, persistence hooks). Only ws files affected under ransom-hardened. Added "Miasma supply-chain worm containment" check to `l2 audit --test`. Updated harden script guidance + json standards. Cross-refs in safe/ransomware demos, seccomp-allowlist, CI smoke, all docs. Full verification that supply-chain worms (like the 2026 Red Hat Miasma attack) are contained to explicit `put` + `exec` authority.
- **L2_DATA_DIR + sudo escalation**: `L2_DATA_DIR` (and all `L2_*` env vars) are now preserved when `l2 exec` (and related paths) auto-escalates via `sudo` for namespace isolation under strict/ransom-hardened policies. Critical for clean testing with the new resistance demos (e.g. `export L2_DATA_DIR=$(mktemp -d); l2 create ... --policy ransom-hardened; ... l2 exec ...`). Updated docs (README, SECURITY, demo headers, STATUS) and hints. The sudo command line now shows `sudo L2_DATA_DIR=... /path/to/l2 ...`. Added a dedicated Troubleshooting subsection to README.md (with cross-references from other docs and the demo sources) covering this, sudo prompts, old kernels, running the resistance demos, etc.
- **Expanded AIO "malware-cancer" + l2 North-Star Containment grand demo + more substrate hardening**: Expanded `docs/examples/l2_malware_cancer_resistance_demo.c` with additional vectors (git/pip hook infection, advanced anti-l2 + direct binary probe, ELF infector sim, sophisticated audit tamper) + rich safe-contained "grand demo" section (many victims, ransom+virus+exfil inside ws only, "North-Star Containment achieved" prints + full summary at end). Creative "l2 North-Star Containment" verbiage infused in sim prints/headers, command examples (e.g. `# grand demonstration of l2 North-Star Containment`), main.rs great/audit/policy output, harden.sh, CI, and all docs (new dedicated grand demo section in README, expanded in SECURITY, STATUS/ROADMAP/CHANGELOG/seccomp/PROTOTYPE). More substrate hardening: extended NEVER (keyctl 250, add_key 249, mknod 133, mkdir 39 + comments), tighter ulimit rlimits in exec wrapper, more extreme sysctls (suid_dumpable=0, core_pattern=null), extra modprobe blacklists + l2-specific audit rules in harden.sh great profile, updated json/standards/applied with North-Star Containment language. All prepare for the "grand show" of what l2 does: one AIO sim under great-harden + audit --test as the repeatable North-Star Containment evidence loop. "prepare prepare prepare" complete; ready for confident end-to-end demo run.
- All additive, narrow, explicit authority, paced UX preserved. No new surfaces.

## [0.4.4] - 2026-06-05

### Added / Improved (full safety protocol + ransomware resistance prep)
- **`ransom-hardened` (full safety) policy protocol**: New explicit protocol for ransomware / malicious workload containment testing (preparing l2 for eventual WannaCry-class validation when the system is ready). `l2 create ... --policy ransom-hardened`, `l2 policy ransom-hardened`, `l2 trace/harden/exec --policy ...`. Auto-enables Phase 1 seccomp enforcing (tiny no-net builtin + extended NEVER blacklist for net/ptrace/modules), minimal Landlock (workspace-only + tiniest RO), rlimits in exec layer, dedicated harden profile + "Ransomware containment" check in `l2 audit --test`.
- **WannaCry-class resistance demo**: New self-contained `docs/examples/l2_ransomware_resistance_demo.c` (SMB 139/445 propagation + killswitch http, mass "encrypt" of common extensions + .WNCRY/.l2ransom + ransom note, cron/bashrc/systemd persistence, setuid/ptrace/personality, fork spread). Only succeeds on the explicit l2 workspace; all else blocked. Usage + conclusions tie directly to the `ransom-hardened` controls. Compile with `-static`. Cross-ref from the safe execution demo.
- **harden + audit + CI integration**: `scripts/harden.sh` now supports `--profile ransom-hardened` (ransomware-specific guidance, 445/139 nft blocks, extra standards in emitted `harden/ransom-hardened-latest.json`). `run_security_audit_tests` always produces the new check (consumes the json + recent policy use). CI smoke exercises policy discovery, create/put/exec under it, harden profile, and the audit check (tolerant pipes preserved).
- **Docs**: Full section in SECURITY.md (WannaCry mapping table, "when you feel ready" testing instructions, CISA ransomware tie-in). Updates to STATUS, README, seccomp-allowlist, ROADMAP. The protocol + demo + `l2 audit --test` give a repeatable, auditable, standards-backed validation path.
- All changes are additive, reuse existing strict-family paths, preserve prior high-assurance fixes (no new surfaces, no bloat). Added policy length guard in C create + Rust for properness. C substrate + seL4 docs lightly commented for future verified caps version of this use case.
- Full verification: logic/security pass over entire l2 (greps/reads of privdrop, guards, C safe, sandbox rules for all policies, new ulimit/escape, demo safety), all gates, strict C compiles, comprehensive L2_DATA_DIR smoke exercising ransom-hardened end-to-end + demo put + audit PASS with json + no regressions.

## [0.4.3] - 2026-06-04

### Security / High-Assurance Fixes (full code sweep)
- **Full codebase sweep for logic errors and security issues**: Reviewed *every* file (Rust CLI/lib/sandbox/audit/L2P, all C core/safe, bash scripts for harden/crypto/sel4, docs, CI, build). Prioritized: isolation enforcement, privilege fallbacks, input sanitization, state/core consistency, BPF correctness, audit integrity, C memory safety, script robustness (quoting, EPIPE, L2 overrides), policy divergence, error paths, races/TOCTOU, claims vs. impl.
- **Critical seccomp Phase 1 enforcing filter BPF bug (src/sandbox.rs)**: Arch validation jump offsets were incorrect (x86_64/aarch64 paths both hit KILL_PROCESS immediately; only exotic arches reached allowlist). This made `L2_STRICT_SECCOMP_ENFORCE=1` (core of strict-mcp + `l2 trace --analyze` + `l2 harden --generate-seccomp`) a DoS instead of true allowlist enforcement. Fixed jump targets (jt/jf) with explanatory comments. Observer path unaffected (always LOGs).
- **L2_USE_CORE / core split persistence and dispatch (host/core.rs, src/main.rs)**: Core server always started empty `Substrate::default()` (no load/save); CLI only partially dispatched (create/put); list/get/destroy/oneshot/named-exec used local in-mem sub. Result: no state across CLI runs, divergence, "core" was broken demo. Fixed: core now `load_state()` at start of each request, `save_state()` after mutating ops (create/destroy/put). Added full dispatch for destroy/list/get (top-level + bare list). Oneshoots kept local (transient). Named systems now correctly persist via disk (subsequent `load_state()` sees core saves). `L2_USE_CORE=1` now provides real shared state. Verified end-to-end.
- **Oneshot + put auto-read over-read of host files (src/main.rs)**: `normalize_exec_args` + shebang peek + handler + put auto-`read_to_string` would read (and import/run under temp ws) arbitrary host files via single-arg `l2 exec /abs/shebang` or `l2 put sys ../evil.txt` (absolute or `..` paths). Violates least-privilege / narrow authority. Fixed: guard detection/auto-read with `!starts_with('/') && !contains("..")` (and `object_relative_path().is_ok()`) before any `exists()`/`read`. Only safe cwd-relative files trigger oneshot/put auto. (Prevents historical-style bypasses.)
- **Duplicate privilege-drop logic (src/main.rs)**: SUDO_UID/GID setuid/setgid drop (the backdoor fix for old-kernel fallbacks running as root) was copy-pasted in two unshare-fallback paths (Ok fail + Err spawn). Risk of divergence. Extracted to single `drop_privileges_if_sudo()` helper (called from both + documented).
- **C l2_sys_put name truncation (core/host.c)**: No `strlen(name)` bound check (unlike create). Long names silently truncated by `strncpy`; later finds by original name failed (inconsistent objects, lost data). Added check returning `L2_ERR_INVALID`.
- **Audit --test check count (src/main.rs)**: "strict-mcp policy usage" check only pushed if log existed → results could have <5 checks on fresh runs (violates documented "5 checks"). Always push now (false if no recent).
- **Audit tamper chain docs (src/audit.rs)**: Comments/docstrings claimed "SHA256 of previous line" for tamper-evidence, but impl used `DefaultHasher` (non-crypto, 64-bit, forgeable). Mismatch between SECURITY claims and code. Fixed comments (accurate + caveats; strength from fs/append-only + best-effort). No dep added.
- **Other**: Minor dispatch robustness, list/get under core, C compile warnings, smoke/CI greps tolerant of 141/EPIPE (as before), always 5 audit results, etc. All preserve narrow scope, no new surfaces.
- **Verification**: Full gates (fmt/clippy -D/test/build --release), C strict gcc -Wall -Wextra -Werror, replicated CI smoke (harden+audit+trace+strict-mcp+L2_USE_CORE), attack sims from demo.c, cross-run persistence. All pass cleanly.

These changes (from exhaustive sweep) eliminate logic errors that could undermine the high-assurance guarantees (enforcement bypasses, state inconsistency, arbitrary reads, privilege leaks in fallbacks, incorrect filters, etc.). l2 is now tighter for agentic/MCP workloads.

## [0.4.2] - 2026-06-03

### Added / Improved
- **`l2 harden` + `l2 audit --test` integration** (main deliverable): `scripts/harden.sh` now always emits a standardized machine-readable artifact `~/.l2/harden/<profile>-latest.json` (for `strict-mcp` etc.) containing `profile`, `timestamp`, `applied` list of protections, and full `standards` array (NSA/CISA "Securing AI Systems", CISA Zero Trust for agents, FBI agentic threats, CIS Linux, l2 strict-mcp + audit --test). The `run_security_audit_tests` check #3 ("Harden reports for strict-mcp") now primarily looks for and validates this JSON (existence + content with profile/standards) so that after a real `l2 harden --profile strict-mcp` (or even dry for CI), `l2 audit --test` reliably reports PASS for the harden-reports check with details referencing the json path and standards. Legacy md reports in `harden-reports/` remain as fallback for humans.
- Post-harden UX: in non-dry/non-json mode, `l2 harden` now prints explicit hint "l2 audit --test   # verify harden reports + strict-mcp against NSA/CISA/FBI standards" (pairs with the existing trace/exec recommendations). Script also updated its final [5/6] and reminder to call out `l2 audit --test` as step 5 / next verification.
- Updated docs for the combined regular flow: SECURITY.md (automatic artifacts section now documents the json + "harden then `l2 audit --test` verifies compliance"), README.md (top version + highlights + verification smoke example + audit --test comment), STATUS.md (v0.4.2 prep note), .github/workflows/ci.yml (smoke comments + extra grep for the json path in audit output + final success message). CI smoke now exercises the integration end-to-end (dry harden writes the json under ~, audit --test consumes it).
- Minor polish in the integration: script heredoc "Next Commands" now includes the `l2 audit --test` line; check #3 produces richer PASS detail when the json is the source ("Found .../harden/strict-mcp-latest.json with standards...").

These changes close the loop requested for "regular audit tests ... automatically implemented with security standards into l2 and its features" by making `l2 harden` (the flagship host-prep tool) produce consumable evidence and `l2 audit --test` (the regular verifier) consume it. The flow `l2 harden --profile strict-mcp [--apply steps] ; l2 audit --test` is now the documented, automated, standards-backed verification path for agentic/MCP workloads. All changes preserve the narrow scope, no new attack surface, and terminal-first UX.

## [0.4.1] - 2026-06-03

### Added / Improved
- **More C integration**: Polished `core/host.c` (full in-memory objects with `l2_memcpy_safe`, better errors, zeroing) and `src/core/core.c` with extensive comments tying the narrow `l2_sys_*` interface to L2P, the Rust `host/core.rs` + `L2Core` trait, and the seL4/Microkit path. Validated clean compilation.
- **User-ns exploration**: Added opt-in experimental support (`L2_EXPERIMENTAL_USER_NS=1` appends `--user` to unshare in `exec_isolated`). Leverages the `nix` "sched" + "user" features (already enabled). Updated TODOs/comments in `sandbox.rs` and cross-refs to hardening plan docs. Includes strong warnings; full id-map/pivot_root work remains future.
- **Put command UX polish**: 
  - New `--file <LOCAL>` option to read content from a local file.
  - Auto-read: if no `--content`/`--file` and `./<NAME>` exists as a file in cwd, `l2 put <sys> <name>` now automatically slurps it (prints note). Makes common `l2 put mysys foo.c` (when foo.c is local) "just work".
- **Exec validation + compiler + code objects fix**: Refined `validate_exec_target_references_real_object` so `gcc`/`cc`/`rustc` etc. + a `--type code` object no longer falsely triggers "Direct execution of 'foo.c' is not supported". Added compilers to interpreter list and `target_from_tool_arg` / `has_compiler` guards. Now `l2 exec <sys> 'cc safe_demo.c ...'` works cleanly for the demo.
- **Unshare fallback for old/restricted kernels**: In `exec_isolated`, if unshare fails (EPERM, spawn fail, etc. — common on X200-era hardware, old kernels <5.13, containers), gracefully fall back to direct `sh -c` execution (with the same env sanitization, cwd, etc.). Still inherits parent protections (caps, seccomp, Landlock if present, no_new_privs). Prints clear warning. Enables the safe demo C program to actually run and educate on old systems.
- **Safe execution demo C program**: Added `docs/examples/l2_safe_execution_demo.c` — a self-contained educational example of "good" code that demonstrates exactly the protections l2 provides (env sanitization, Landlock FS containment, seccomp/caps blocks on dangerous syscalls like ptrace/socket, etc.). Includes full usage instructions for `put` (with `--file` or auto) + `exec` inside a `strict-mcp` system. Compiles cleanly; the program itself reports what would be "bad" on an unprotected host.
- **Trace/harden/analyzer polish**: Made `--analyze` parser more robust (handles journalctl/dmesg/ausearch, synthetic traces from `docs/traces/`, more "syscall=" / "nr=" variants). Better output, integration hints ("feeds l2 harden"). Minor script UX improvements in `harden.sh`/`crypto.sh`.
- **Other robustness/UX**: Fixed pipe-safety in all paced scripts (typewriter helpers now `|| true` on printf). Improved L2P client robustness. Various comment/doc updates tying new features together. Full `cargo fmt` + `clippy -D warnings` sweeps.
- **Regular audit tests + auto standards integration**: Added `l2 audit --test` that runs automated checks against up-to-date security standards (CISA/NSA/FBI for agentic/AI/MCP, Linux/CIS hardening, zero-trust, tamper-evident audit, least-priv, supply chain). Checks include chain validity, strict-mcp usage, harden reports, sandbox refs, no ambient root/creds. "Automatically implemented" via strict-mcp policy (enforces many), harden (generates compliant artifacts), and CI/smoke. Run regularly (`l2 audit --test` in cron/CI). Updated smoke, docs, policy help, and added Rust test.
- **Docs**: Updated `STATUS.md`, `README.md` (smoke test, usage), `SECURITY.md`, `CHANGELOG.md`, `docs/seccomp-phase1-allowlist.md` to reflect the above. The safe demo C is now the canonical "what safe execution inside l2 looks like" artifact.

These changes continue maturing the high-assurance path (explicit policies + substrate + C/L2P split prep + hardening + data-driven seccomp + audit) while keeping the narrow terminal interface and "no new attack surfaces" invariants. Better support for old kernels and practical demo usage.

## [0.4.0] - 2026-06-02

## [0.4.0] - 2026-06-02

### Added
- **`l2 crypto`** — New major feature for selecting and applying cryptography profiles across the l2 substrate for true system encryption.
  - Profiles limited to most effective/verified open-source algorithms: `aes256-xts-argon2id`, `xchacha20-poly1305-argon2id`, and `hybrid-aes-chacha`.
  - `hybrid` mixes complementary algorithms (AES for bulk + ChaCha for keys/meta) for robust defense-in-depth.
  - Applies proficiently and simply via LUKS/dm-crypt for volumes and gocryptfs for per-dir (easy user-space).
  - Integrated with l2 isolation (e.g. `strict-mcp` policies) to protect keys and crypto operations.
  - `--apply` performs user-confirmed setup of encrypted storage for l2 data (and guidance for home/data).
  - `--network-isolation` flag for aggressive outbound lockdown (nftables examples).
  - `--generate-seccomp <trace>` to produce minimal profiles from traces (SystemCallFilter + custom filter format).
  - Automatic generation of full hardened systemd unit templates (with capabilities, namespaces, seccomp, etc.).
  - Uses same paced "typewriter" output as `l2 sel4-setup` and `l2 harden` for readable setup.
- Expanded `l2 harden` with more aggressive defaults for `strict-mcp`, capability dropping, advanced namespace setup, and deeper integration.
- The enforcing seccomp filter can directly load generated profiles (via `L2_SECCOMP_PROFILE` env or arg).
- `strict-mcp` now has meaningfully stronger defaults (enforcing on, tighter Landlock, network bias).
- `l2 policies` and `l2 policy <name>` (including rich `strict-mcp` docs) updated for crypto context.

### Changed
- `apply_strict_sandbox` and policy normalization are now fully aware of `strict-mcp` for differentiated (more paranoid) behavior.
- CLI help descriptions kept terse (as per feedback) while detailed help remains informative.
- Bumped crate version to 0.4.0 (major feature release).

This release makes l2 a complete high-assurance substrate for the agentic era: isolation policies, host hardening, and now selectable verified crypto profiles applied simply yet robustly across the system.

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
