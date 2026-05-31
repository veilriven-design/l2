# Status

**Refocused narrow substrate phase** — now actually usable

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
- Basic sandboxing for `--policy strict` (no_new_privs + Landlock hooks)
- **Full `l2 sel4-setup` command**: one-command seL4/Microkit bootstrap with:
  - Official Microkit SDK 2.2.0 tarball download
  - Distro-aware behavior (especially strong support for RHEL/Fedora + podman)
  - Automatic pre-pull of base images using `docker.io/trustworthysystems/...` fully-qualified names (bakes in the fix for Podman's "short-name resolution enforced but cannot prompt without a TTY" error on RHEL)
  - Automatic offer + live spinner to set up the official seL4/CAmkES development container on RHEL+podman
  - High-quality generated `README-l2-sel4.md` with the RHEL/Podman one-time fix permanently documented
- Dramatically improved `list` output and overall UX
- `demo.sh` removed (commands documented directly in README instead)

## Current Focus

1. Better host isolation (more namespaces, seccomp, user namespaces, Landlock, etc.)
2. Out-of-process `l2-core` speaking the real L2P protocol over stdio/socket
3. Start the disciplined C implementation of the core
4. seL4/Microkit backend (parallel track) — `l2 sel4-setup` is the current on-ramp

## How to Use Right Now

```bash
cargo build --release

# Basic usage (works across separate shells)
l2 create my-agent
l2 put my-agent code foo.rs --content 'fn main(){}'
l2 exec my-agent 'echo hello from inside'
l2 list my-agent
l2 destroy my-agent

# seL4 development environment (recommended path)
l2 sel4-setup
cat ~/l2-sel4-workspace/README-l2-sel4.md
```

Override data location with `L2_DATA_DIR=/some/path l2 ...`

## Out of Scope
Effect systems, lattices, packaging, physics work, scope creep.

Keep it small. Keep it terminal. Keep it high-assurance.
