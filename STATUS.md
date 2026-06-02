# Status

**v0.4.4 released** — Full safety protocol + ransomware resistance prep: new explicit `ransom-hardened` policy (auto-enforcing seccomp, minimal ws-only Landlock, rlimits, dedicated harden); self-contained `docs/examples/l2_ransomware_resistance_demo.c` (WannaCry-class sim: SMB, encrypt+.WNCRY, persistence, priv esc — only ws succeeds); `scripts/harden.sh` + `l2 audit --test` integration for ransomware containment check + `ransom-hardened-latest.json`; CI/docs updates. All additive. See CHANGELOG.md. Builds on v0.4.3 (security sweep). v0.4.3 tag preserved.
- New `l2 harden` command + `scripts/harden.sh` (modeled after sel4-setup with paced typewriter output). Applies NSA/CISA/FBI-aligned concrete hardening steps for the agentic era.
- `strict-mcp` policy protocol is now the main focus: diverges from `strict` with aggressive defaults (enforcing seccomp on by default, tighter posture).
- Full integration: `l2 trace --policy strict-mcp` + `--analyze`, `l2 harden --generate-seccomp`, and the runtime enforcing filter can directly load generated minimal profiles.
- Automatic generation of hardened systemd unit templates from `l2 harden`.
- New commands: `l2 policies` and `l2 policy <name>` (especially `l2 policy strict-mcp`).
- Significant maturity in seccomp tooling, capability/namespace guidance, and network isolation options.
- `l2 harden --network-isolation` and concrete host hardening steps (sysctls, dedicated users, audit rules, etc.).

This release makes `strict-mcp` + `ransom-hardened` + `l2 harden` + `l2 audit --test` a real, operational high-assurance path for MCP/agentic and ransomware containment validation workloads. v0.3.2 and earlier tags preserved.

## Charter

l2 is the minimal high-assurance Latticra substrate:
- Dynamic, on-demand isolated execution contexts
- Driven exclusively from the terminal (CLI primary interface)
- Tiny public surface
- Total cleanup on destroy
- Extreme restraint on scope and code

## Done (Current Prototype)

- Refocus + narrow docs (TERMINAL_INTERFACE, PROTOCOL, etc.)
- Working Rust CLI with **full command surface** (create/put/get/exec/list/destroy/status/revoke + `--json`)
- **Real persistence**: systems + objects survive across separate `l2` invocations (stored in `~/.l2/state.json`)
- Real Linux namespace isolation for `exec` (`unshare`)
- **Real Landlock + no_new_privs sandboxing for `--policy strict`**: workspace-confined writes, RO+EXEC on system essentials (v0.2.0)
- **Explicit policy protocols** (`default`, `strict`, `strict-mcp` (main focus for agentic/MCP), `ransom-hardened` (full safety for ransomware/malicious testing)) with clear guarantees and `l2 policies` / `l2 policy <name>` discovery.
- **Full `l2 sel4-setup` command**: one-command seL4/Microkit bootstrap with:
  - Official Microkit SDK 2.2.0 tarball download (clear primary/fast path)
  - Distro-aware behavior (especially strong support for RHEL/Fedora + podman)
  - Automatic pre-pull of base images using `docker.io/trustworthysystems/...` fully-qualified names (bakes in the fix for Podman's "short-name resolution enforced but cannot prompt without a TTY" error on RHEL)
  - On RHEL+podman: heavy time/hardware warnings (hours to 40h+ on ancient/low-RAM machines); SDK + host cross tools presented as the default; full container requires typing an explicit confirmation phrase (v0.3.1 UX hardening for old hardware like X200-class systems)
  - High-quality generated `README-l2-sel4.md` with the RHEL/Podman one-time fix permanently documented and strong guidance on choosing the right path by hardware capability
- **Dramatically improved `list` output and overall UX**
- `demo.sh` removed (commands documented directly in README instead)
- **`l2 crypto`** (v0.4.0): Select and apply verified crypto profiles (`aes256-xts-argon2id`, `xchacha20-poly1305-argon2id`, `hybrid-aes-chacha`) for true system encryption (LUKS + gocryptfs). Hybrid mixes complementary algorithms. Applied proficiently with paced typewriter output; keys protected by l2 isolation (strict-mcp / ransom-hardened). Includes `--apply`, `--network-isolation`, `--generate-seccomp`, and auto-generated hardened systemd units.
- **`l2 harden`** (v0.4.0+): NSA/CISA/FBI-aligned concrete host/container hardening for the agentic era. Paced output, `--network-isolation`, capability dropping, advanced namespaces, automatic systemd unit generation, and trace-driven seccomp profiles. Supports `strict-mcp` and `ransom-hardened` profiles (ransomware-specific blocks, standards in json). `strict-mcp` profile is the main focus and has aggressive defaults (enforcing on by default, tighter Landlock).
- **`l2 trace`** with policy support (incl. `ransom-hardened`), `--analyze`, and `--output-profile` to generate real minimal seccomp profiles that the runtime enforcing filter + strict-mcp / ransom-hardened auto-discovery load directly (via `L2_SECCOMP_PROFILE` or `~/.l2/seccomp/...`).
- More C integration (core/host.c + src/core/core.c polished with L2P/seL4/Rust ties + safe.c usage), user-ns exploration (L2_EXPERIMENTAL_USER_NS=1 + nix sched), and ongoing trace/harden/overall polish (analyzer robustness, script UX, quality gates, L2P/C consistency).
- Full integration between policies (strict-mcp + ransom-hardened + great-harden), crypto, trace data, host hardening (`l2 great-harden` for supreme), and `l2 audit --test` (consumes harden json artifacts). All long guidance uses readable paced "typewriter" output (disable with `--fast`).
- Dramatically improved `list` output and overall UX (repeated for emphasis on v0.4+ polish)

## Current Focus

1. **Agentic/AI/MCP hardening track (v0.4.0+ main focus; next: #7) + great-harden for aerospace/industrial**: `l2 crypto` + `strict-mcp` + `ransom-hardened` + `l2 harden` + `l2 audit --test` + **NEW `l2 great-harden`** as a complete, operational high-assurance path (incl. ransomware containment validation + Miasma supply-chain worm resistance via dedicated demo + supreme aerospace/industrial impenetrable mode). Further per-protocol divergence, more aggressive defaults in crypto/harden, deeper integration of generated seccomp profiles into runtime, and expanded concrete steps + direct consumability in `l2 harden` (more distros, automated unit/profile application, --apply for real state changes; see GitHub #7). `great-harden` closes remaining logic gaps for critical complexes.

   **New: ransom-hardened (full safety) policy + WannaCry-class + Miasma supply-chain resistance prep + great-harden supreme + AIO malware-cancer + l2 North-Star Containment grand demo**: Explicit `ransom-hardened` protocol (auto-enforcing, minimal Landlock ws-only, rlimits, dedicated harden profile + audit checks "Ransomware containment" and "Miasma supply-chain worm containment"). Includes self-contained educational sims `docs/examples/l2_ransomware_resistance_demo.c` (SMB 445/killswitch, mass encrypt+.WNCRY, persistence, priv esc — only ws files succeed) and `l2_miasma_resistance_demo.c` (npm preinstall + OIDC credential theft + "Miasma: The Spreading Blight" exfil/repack/propagation — only ws files affected). `l2 create ... --policy ransom-hardened ; ... exec ... ; l2 audit --test` now exercises full substrate for ransomware + supply-chain worm resistance. **NEW `l2 great-harden`**: supreme higher-assurance for aerospace/industrial/critical (closes logic gaps, extreme configs for impenetrable servers to malware/worms/viruses, great-harden policy, aerospace lockdown). **AIO "malware-cancer" attack sim + l2 North-Star Containment grand demo** (`docs/examples/l2_malware_cancer_resistance_demo.c`): named comprehensive attack on the l2 substrate (ransom + Miasma + viruses + direct state/trace/audit/crypto tamper + ns/bpf/setns/unshare escapes + fork/priv-esc + git/pip/ELF/anti); substrate prepared (extended NEVER etc.) + validated via great-harden + audit check for North-Star Containment. This is the grand demonstration of what l2 does. Prepares for real testing "when ready". See SECURITY.md, README Troubleshooting, and the demo headers.

   **Recent concrete improvements to crypto + MCP hardening (incl. v0.4.4 full-safety):**
   - Capability bounding set fully dropped (PR_CAPBSET_DROP) for all strict/strict-mcp/ransom-hardened workloads.
   - strict-mcp / ransom-hardened Landlock: no ambient /tmp (even RO) — workspace is the only writable and now the only visible tmp surface.
   - Seccomp profiles: auto-discovery for strict-mcp/ransom-hardened from l2 data dir + /etc/l2; `l2 trace --analyze --output-profile` produces directly loadable files; `l2 harden --generate-seccomp` now writes them too.
   - Crypto: --apply produces MCP-aware helper script, stronger integration guidance for protecting l2 state + keys under strict-mcp (and ransom-hardened for testing).
   - `l2 harden --profile ransom-hardened` + `ransom-hardened-latest.json` + "Ransomware containment" + "Miasma supply-chain worm containment" checks in `l2 audit --test`.
   - Audit events now emitted for `l2 crypto` and `l2 harden` invocations.
   - **Next immediate (GitHub #7)**: Direct consumability for harden artifacts (`l2 harden --apply` etc.) so guidance becomes audited, repeatable applied state (units, profiles, rules). Matches the "make generated ... directly consumable" item.

2. Better host isolation (seccomp-bpf, capability dropping, tighter Landlock policies, user+mount ns) — Landlock baseline v0.2.0. Phase 0 complete: real `SECCOMP_RET_LOG` + `FLAG_LOG` observer now works (`L2_STRICT_SECCOMP_OBSERVE=1`). Kernel audit logs for strict workloads are available. Phase 1 enforcing active and exercised by strict-mcp + ransom-hardened. See `src/sandbox.rs` + docs/PROTOTYPE_HARDENING_AND_SEL4_PLAN.md for usage. Ready for trace collection → profiles. (Now heavily exercised by `strict-mcp`, `ransom-hardened`, and crypto tooling.)

3. Audit logging: Basic append-only JSONL authority audit log (`audit.log` in data dir) now implemented for create/put/exec/destroy/revoke/escalate/sandbox (and oneshot temp systems). Includes `l2 audit` subcommand. Respects SUDO_USER. See `src/audit.rs`. This directly addresses the "Evidence and audit" requirement in SECURITY.md.

4. Correctness gaps: Deeper work — non-panicking JSON output paths, load_state now warns on corrupt JSON, many silent cleanups now use warn_on_cleanup_err, 17 tests (strong coverage on data_dir, state roundtrips, error paths, isolation helpers). See recent changes in src/main.rs.

5. Architecture prep for core split: l2-core binary now implements basic L2P handler (ping/status over stdio). See host/core.rs. Clear boundary (trait + out-of-process) and C core work next. The main `l2` prototype remains the daily driver.

6. seL4/Microkit backend (parallel track) — `l2 sel4-setup` is the current on-ramp (now complemented by `l2 harden`/`l2 crypto` for secure agentic environments on the host). Out-of-process `l2-core` speaking the real L2P protocol and disciplined C implementation remain active focus.

## How to Use Right Now

See [ROADMAP.md](ROADMAP.md) for the current prioritized direction.

See the full install + usage instructions (and the dedicated Troubleshooting subsection) in `README.md` (covers both `cargo build --release` and `cargo install --path . --force`).

Quick reference:
```bash
cargo build --release          # or cargo install --path . --force
l2 create demo --policy strict
l2 put demo note.txt --content 'hello'
l2 exec demo 'cat note.txt'
l2 destroy demo
l2 sel4-setup
# For aerospace/industrial + grand l2 North-Star Containment demo: l2 great-harden --apply ; l2 create critical --policy great-harden ; l2 put ... l2_malware_cancer_resistance_demo.c ; l2 exec ... ; l2 audit --test  # North-Star Containment verified
```

Override state with `L2_DATA_DIR=/path l2 ...` (fully supported, including through `l2 exec`'s automatic sudo escalation for namespace isolation under strict/ransom-hardened policies). See the Troubleshooting section in README.md for common gotchas and solutions.

## Out of Scope
Effect systems, lattices, packaging, physics work, scope creep.

Keep it small. Keep it terminal. Keep it high-assurance.
