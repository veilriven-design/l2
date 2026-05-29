# Security Model and Assurance Approach

l2 is designed for a **very high** threat model. The substrate must protect developer workflows and MCP operations against sophisticated adversaries, including supply-chain attacks, compromised host environments, and attempts to escape containment.

## Threat Model

- Adversaries may have code execution on the host operating system.
- MCP servers and other workloads running inside l2 may be malicious or compromised.
- Supply chain attacks against build tools, dependencies, or the host are in scope.
- Physical access and sophisticated side-channel or fault-injection attacks are out of scope for the initial design (future hardware platforms such as CHERI may change this).
- The goal is strong containment: a successful compromise of one workload inside l2 should not allow escape to other workloads or to the host except through explicitly authorized, narrow, auditable channels.

## Design Principles

1. **seL4 as the root of trust** — We rely on seL4's machine-checked isolation, capability, and integrity properties rather than attempting to re-verify a new kernel.
2. **Minimal userland TCB** — The code that runs with authority to create or manage containment vectors must be as small as possible and written in a disciplined subset of C.
3. **Explicit authority and contracts** — No operation that can affect another domain or the host is permitted without an explicit, logged authorization decision.
4. **Least privilege by default** — Every protection domain (workload) receives only the exact capabilities required for its declared purpose.
5. **Narrow host interface** — The only way in or out of the containment vector from the host terminal is through a small, carefully reviewed shim and protocol.
6. **Evidence and audit** — All boundary crossings and authority grants are recorded in a form that supports later forensic analysis.

## Memory Safety in C

C is the implementation language for the substrate core. We treat memory safety as a first-class engineering problem:

- Strict coding rules (bounds-checked data structures, no unchecked pointer arithmetic in security-critical paths, explicit ownership).
- Mandatory static analysis on every change that touches the containment boundary or capability handling.
- Avoidance of undefined behavior; use of seL4's own verified runtime components where possible.
- Long-term hardware acceleration path: CHERI (or equivalent) to make spatial memory safety a hardware-enforced property for C code.

We do not claim memory safety equivalent to a memory-safe language in the initial implementation. The combination of seL4 isolation + rigorous process + future CHERI is the strategy.

## Alignment with External Guidance

We track and apply the technical recommendations from:

- CISA "Secure by Design" principles and memory safety initiatives
- NSA guidance on memory safety, least privilege, and reducing the attack surface of critical systems
- General high-assurance engineering practices used in formally verified and high-consequence systems

We make no claim to have achieved any specific certification or formal "compliance" at this stage. The project is structured so that the architecture, code, build process, and evidence artifacts can support such claims in the future if desired.

## Reporting Security Issues

See the process in the repository security policy (to be added) or contact the maintainers through the channels listed in the repository.

Vulnerabilities that affect the containment boundary or allow escape between domains or to the host are treated as critical.
