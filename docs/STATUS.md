# Status

**v0.5.9** — North-Star Attack + North-Star Defense: research + implementation of the most mathematically dangerous directed network attack exploiting *inherent* flaws in binary computers (IEEE 754 NaN/denormal timing side-channels, two's complement casts/overflow, FP precision/accumulation "catastrophes", Inf/NaN propagation, payload-bit weird machines, consensus splits from net "numeric" streams). Universal (no sw patch); diabolical payload looks like valid sensor/AI/MCP data. "North-Star Defense": on l2 hardened (great-harden + explicit net surfaces na/tomato + spirit --file raw math patterns now flagged + `l2 audit --test` new check + resistance demo) you are protected/safe — attack only "succeeds" (bypass, exfil, catastrophe, weird compute) inside explicit disposable authorized ws; damage contained, fully evidenced, disposable. Fits prepare/NSA-CISA/MCP numeric isolation. Builds on v0.5.8 tomato/na + prior RAT/spinner/great. "prepare prepare prepare".
**v0.5.8** — Integrate `tomato` router network tool + `na` network-audit/pentest (masked substrate surfaces for contained network security testing that complement each other). Full codebase RAT etc from v0.5.7 + spinner/progress for --audit --os + tomato/na. `l2 spirit --audit --rat` ... (same). New: standalone `na` + `tomato` bins (cargo build --release --bin na --bin tomato). --policy na: masked disposable "na0" surface for Wireshark/Aircrack-style capture/inject/scan/wifi-sim. --policy tomato: richer wan0+lan0 router surface (forwarding, NAT) + tomato CLI (firewall nft, qos tc, monitor, wan/lan config like Tomato firmware). They complement perfectly (tomato configures/protects the virtual router; na audits/pentests it from the surface). All contained in ws+netns, strict sandbox, net:raw/router grants, fully disposed on destroy. Host sees only masked veth peers. Fits North-Star, prepare, evidence, no new surfaces. Builds on v0.5.6/7. "prepare prepare prepare".
  - `--audit --os` : full OS scan for malicious code and bad logic anywhere (suid, droppers, cron, escapes, priv, etc; 7+ checks, PASS/REVIEW, CISA 4.A + l2 demos).
  - `--audit --file <PATH>` : audit any source or file for safe vs dangerous code logic (NEVER blacklist syscalls, dropper patterns, l2 substrate attacks, TOCTOU, priv esc from full-weakness/cancer/redteam/ransom demos). Outputs verdict (SAFE/DANGEROUS/REVIEW) + findings + containment recs.
  Builds on prior L2P/Host, operational harden, North-Star. Old `audit --os-scan` still delegates.

External interface, L2_DATA_DIR (sudo), policies (great-harden for aerospace/industrial impenetrable + North-Star Containment), resistance demos (malware-cancer AIO + crypto redteam + full-weakness + quantum), `l2 audit --test` (10+ checks + "l2 North-Star Containment" phrasing + standards from CPG/MCP/Agentic/quantum/2026 sweeps) all unchanged. PQC/liboqs + full NSA/CISA 2026 alignment + "prepare prepare prepare" ethos preserved. This qualifies the major version: real out-of-proc L2Core E2E + direct consumable harden + seL4 path credible (less "prototype" language). v0.4.9 and prior tags preserved.
- New `l2 harden` command + `scripts/harden.sh` (modeled after sel4-setup with paced typewriter output). Applies NSA/CISA/FBI-aligned concrete hardening steps for the agentic era.
- `strict-mcp` policy protocol is now the main focus: diverges from `strict` with aggressive defaults (enforcing seccomp on by default, tighter posture).
- Full integration: `l2 trace --policy strict-mcp` + `--analyze`, `l2 harden --generate-seccomp`, and the runtime enforcing filter can directly load generated minimal profiles.
- Automatic generation of hardened systemd unit templates from `l2 harden`.
- New commands: `l2 policies` and `l2 policy <name>` (especially `l2 policy strict-mcp`).
- Significant maturity in seccomp tooling, capability/namespace guidance, and network isolation options.
- `l2 harden --network-isolation`, `l2 net-isolate` (new standalone first-class option), and concrete host hardening steps (sysctls, dedicated users, audit rules, etc.). net-isolate is additive, scoped correctly (per-uid), integrates audit/evidence, does not weaken core per-process or great-harden forcing.

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
- **`l2 crypto`** (v0.4.0; v0.4.7+ even further polish; v0.4.8 release + quantum prep): Select and apply verified crypto profiles (`aes256-xts-argon2id`, `xchacha20-poly1305-argon2id`, `hybrid-aes-chacha`, `hybrid-pqc-mlkem-chacha`, `pqc-mlkem-argon2id`) for true system encryption (LUKS + gocryptfs). Hybrid mixes complementary algorithms; PQC profiles use open-source liboqs (ML-KEM / Kyber NIST FIPS 203) for key encapsulation + strong sym to defend quantum attacks (Shor/Grover, harvest now decrypt later). Applied proficiently with paced typewriter output; keys (incl PQC privkeys) protected by l2 isolation (strict-mcp / ransom-hardened). Includes `--apply`, `--network-isolation`, `--fast`, `--json`, L2_DATA_DIR/crypto/ + crypto-latest.json evidence for audit (now includes PQC standards). Dedicated `l2_crypto_redteam_onslaught.c` (10 NSA-level vectors + quantum harvest; PQC defense + GRAND SUMMARY + HOWTO) for red-team verification of standards (KDF/side/exfil/misuse/RNG/hybrid/tamper/supply/l2-state/passphrase/impl + quantum); full closed loop with great-harden + put/exec + audit --test. See crypto section + "prepare prepare prepare".
- **`l2 harden`** (v0.4.0+): NSA/CISA/FBI-aligned concrete host/container hardening for the agentic era. Paced output, `--network-isolation`, capability dropping, advanced namespaces, automatic systemd unit generation, and trace-driven seccomp profiles. Supports `strict-mcp` and `ransom-hardened` profiles (ransomware-specific blocks, standards in json). `strict-mcp` profile is the main focus and has aggressive defaults (enforcing on by default, tighter Landlock).
- **`l2 trace`** with policy support (incl. `ransom-hardened`), `--analyze`, and `--output-profile` to generate real minimal seccomp profiles that the runtime enforcing filter + strict-mcp / ransom-hardened auto-discovery load directly (via `L2_SECCOMP_PROFILE` or `~/.l2/seccomp/...`).
- More C integration (core/host.c + src/core/core.c polished with L2P/seL4/Rust ties + safe.c usage), user-ns exploration (L2_EXPERIMENTAL_USER_NS=1 + nix sched), and ongoing trace/harden/overall polish (analyzer robustness, script UX, quality gates, L2P/C consistency).
- Full integration between policies (strict-mcp + ransom-hardened + great-harden), crypto, trace data, host hardening (`l2 great-harden` for supreme), and `l2 audit --test` (consumes harden json artifacts) + new `--os-scan` for full-host malicious code/bad-logic detection (v0.5.4). All long guidance uses readable paced "typewriter" output (disable with `--fast`).
- Dramatically improved `list` output and overall UX (repeated for emphasis on v0.4+ polish)

## Current Focus

1. **v0.5.6 (l2 net-isolate + audit fixes + UX)**: `l2 net-isolate` (standalone nft isolation option, scoped correctly, additive, integrates audit/evidence). Plus fixes so `spirit --audit --os` gives true PASSes on good/normal things (root, ssh keys, systemd, cargo temps). Spirit audit + terse subcmd helps. Builds on prior. "prepare prepare prepare".

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

3. Audit logging: Basic append-only JSONL authority audit log (`audit.log` in data dir) now implemented for create/put/exec/destroy/revoke/escalate/sandbox (and oneshot temp systems). Includes `l2 audit` subcommand. Respects SUDO_USER. See `src/audit.rs`. This directly addresses the "Evidence and audit" requirement in docs/SECURITY.md.

4. Correctness gaps: Deeper work — non-panicking JSON output paths, load_state now warns on corrupt JSON, many silent cleanups now use warn_on_cleanup_err, 17 tests (strong coverage on data_dir, state roundtrips, error paths, isolation helpers). See recent changes in src/main.rs.

5. L2P / core split **mature for v0.5.0**: l2::Host (Linux) + L2Core trait + l2-core (host/core.rs) now provide real E2E exercised narrow boundary for create/put/exec-intent (L2_USE_CORE=1 path). Heavy host primitives stay in CLI wrapper for exact compat (L2_DATA_DIR/sudo/escalate/sb). seL4 PD (src/core/core.c) + C host impl (core/host.c) + safe layer implement the *same* surface. External iface + North-Star grand demos + audit evidence identical. "l2 host prototype (persistent)" language softened.
6. **RAT defense (v0.5.7)**: After full eval, added --rat mode + patterns in spirit (file + dedicated OS RAT scan), updated --os regexes, new check in audit --test, harden note. Mechanism: detect (spirit), contain (net-isolate + great + NEVER), revoke, evidence. No new surfaces.

6. seL4/Microkit backend (parallel track, v0.5.0 traction): `l2 sel4-setup` on-ramp + C PD skeleton (src/core/core.c) + shared safe FFI + narrow l2_sys_* (core/host.c) + L2P surface now dual-implemented with the mature Rust l2::Host. The narrow contract means a future PD can replace the Linux Host with zero change to CLI, policies (great-harden), North-Star demos, or audit evidence. L2P v1 exercised E2E on Linux today is the prerequisite.

## How to Use Right Now

See [docs/ROADMAP.md](ROADMAP.md) for the current prioritized direction.

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
# North-Star Attack/Defense (binary math net payload): l2 great-harden --apply ; l2 create ns --policy great-harden ; l2 put ... l2_northstar_attack_resistance_demo.c ; l2 exec ... ; l2 audit --test  # new "North-Star attack ... containment — l2 North-Star Defense" PASS + SUMMARY (universal flaw contained)
```

Override state with `L2_DATA_DIR=/path l2 ...` (fully supported, including through `l2 exec`'s automatic sudo escalation for namespace isolation under strict/ransom-hardened policies). See the Troubleshooting section in README.md for common gotchas and solutions.

## Out of Scope
Effect systems, lattices, packaging, physics work, scope creep.

Keep it small. Keep it terminal. Keep it high-assurance.
