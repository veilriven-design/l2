# Status

**Refocused narrow substrate phase** — host prototype active

## Charter

l2 is the minimal high-assurance Latticra substrate:
- Dynamic, on-demand isolated execution contexts
- Driven exclusively from the terminal (CLI/TUI primary interface)
- Tiny public surface (`l2` command + `l2_sys_*`)
- Total cleanup on destroy
- Extreme restraint on scope and code

## Done

- Refocus PR merged (narrow charter, terminal-first docs, aggressive pruning)
- `docs/TERMINAL_INTERFACE.md` — primary UX specification
- `docs/PROTOCOL.md` — L2P v1 narrow protocol defined
- First **runnable host prototype** (`cargo build && ./target/release/l2`)
  - Full command surface from the terminal design (create/put/exec/get/list/destroy/status)
  - In-memory substrate simulation with colored, scriptable output + `--json`
  - Matches the "Grok Build TUI spirit" of direct, precise terminal interaction

## Current Focus (Next Pieces)

1. Real host isolation backend (Linux namespaces / unshare / seccomp / pivot_root) behind the same CLI and protocol
2. Out-of-process core that speaks L2P over stdio or unix socket
3. Start disciplined C implementation of the core (memory safety guards first)
4. seL4/Microkit path as the strong target (parallel track)

## Immediate Developer Workflow

```bash
cargo run -- create demo --policy default
cargo run -- put demo code main.rs --content "fn main(){}"
cargo run -- exec demo "echo hello"
cargo run -- --json list
```

## Explicitly Out of Scope

- Effect systems, lattices, multi-model frameworks
- Packaging, installers, distribution contracts
- Physics/proof/simulation work
- Anything that increases the conceptual surface area

Keep it small. Keep it terminal. Keep it high-assurance.

Moving deliberately with working code.
