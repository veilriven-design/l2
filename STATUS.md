# Status

**Refocused narrow substrate phase** — host prototype with real isolation

## Charter

l2 is the minimal high-assurance Latticra substrate:
- Dynamic, on-demand isolated execution contexts
- Driven exclusively from the terminal (CLI/TUI primary interface)
- Tiny public surface (`l2` command + `l2_sys_*`)
- Total cleanup on destroy
- Extreme restraint on scope and code

## Done

- Refocus PR merged + narrow docs (TERMINAL_INTERFACE, PROTOCOL, SYSTEM_MODEL)
- Working Rust CLI with full surface + `--json`
- **Real host isolation**: `exec` now runs under `unshare --fork --pid --mount-proc --net` (actual Linux namespaces)

## Current Focus

1. Out-of-process core speaking L2P v1 over stdio/unix socket (split client/core)
2. Disciplined C core implementation (sys.h surface + memory safety + host backend)
3. seL4/Microkit integration track (parallel)

## Developer Workflow (now with real isolation)

```bash
cargo build --release
l2 create demo
l2 exec demo "id"          # runs in isolated namespaces
l2 --json status
```

## Out of Scope
Effect systems, lattices, packaging, physics work, scope creep.

Keep it small. Keep it terminal. Keep it high-assurance.
