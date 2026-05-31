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
- Working Rust CLI with full command surface
- **Real persistence**: systems + objects survive across separate `l2` invocations (stored in `~/.l2/state.json`)
- Real Linux namespace isolation for `exec` (`unshare`)
- Dramatically improved `list` output and overall UX

## Current Focus

1. Better host isolation (more namespaces, seccomp, user namespaces, etc.)
2. Out-of-process `l2-core` speaking the real L2P protocol over stdio/socket
3. Start the disciplined C implementation of the core
4. seL4/Microkit backend (parallel track)

## How to Use Right Now

```bash
cargo build --release

# Works across separate shell sessions
l2 create my-agent
l2 put my-agent code foo.rs --content 'fn main(){}'
l2 exec my-agent 'echo hello from inside'
l2 list my-agent
l2 destroy my-agent
```

Override data location with `L2_DATA_DIR=/some/path l2 ...`

## Out of Scope
Effect systems, lattices, packaging, physics work, scope creep.

Keep it small. Keep it terminal. Keep it high-assurance.
