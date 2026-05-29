# l2 Status

**Current phase**: Skeleton and architectural definition.

## Recent Work

- Project repository initialized under veilriven-design/l2
- Tight README and SECURITY.md established
- Core concepts (containment vector, terminal host interface, MCP focus) captured

## Near Term (First Milestone)

- Define the minimal containment vector abstraction on seL4/Microkit
- Reproducible build for seL4 + Microkit under QEMU (aarch64 and x86_64)
- Basic host terminal shim that can create and interact with a containment vector
- Initial narrow protocol between host and l2 substrate

## Principles for All Work

- Every added line of code or documentation must justify itself against the mission of minimal high-assurance MCP and developer computation.
- The containment boundary and any code that manages authority are held to the highest review standards.
- We favor proven seL4 ecosystem components (Microkit, sel4runtime, etc.) over new inventions in the early stages.
