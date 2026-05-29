# Architecture Overview

l2 is deliberately minimal.

## Layers

1. **seL4** — The verified microkernel. Provides capabilities, threads, IPC, virtual memory, and strong spatial/temporal isolation. This is the root of trust.

2. **Containment Vector (l2 core)** — A thin userland layer (initially using seL4 Microkit protection domains) that creates, manages, and enforces isolated execution contexts. This is the substrate proper.

3. **Workloads** — MCP servers, developer tasks, and other computations that run inside containment vectors. They receive only explicitly delegated authority.

4. **Host Terminal Interface** — A narrow, authenticated channel from the ordinary terminal on the host OS into the containment vector. This is the only developer/operator surface.

## Key Invariant

Nothing inside a containment vector can affect anything outside it (other vectors or the host) except through the explicit mechanisms provided and audited by the l2 core.

The design favors static or mostly-static architectures that are easier to reason about and analyze over fully dynamic ones.
