# Security Model and Assurance Approach

l2 is designed for a **very high** threat model. The substrate must protect developer workflows and MCP operations against sophisticated adversaries, including supply-chain attacks, compromised host environments, and attempts to escape containment.

The terminal operator working through the narrow `l2` CLI/TUI is the only source of new authority. This is a core security property.

## Threat Model

- Adversaries may have code execution on the host operating system.
- MCP servers and other workloads running inside l2 may be malicious or compromised.
- Supply chain attacks against build tools, dependencies, or the host are in scope.
- Physical access and sophisticated side-channel or fault-injection attacks are out of scope for the initial design (future hardware platforms such as CHERI may change this).
- The goal is strong containment: a successful compromise of one workload inside l2 should not allow escape to other workloads or to the host except through explicitly authorized, narrow, auditable channels.

## Design Principles

1. **seL4 as the root of trust** — We rely on seL4's machine-checked isolation, capability, and integrity properties rather than attempting to re-verify a new kernel.
2. **Minimal userland TCB** — The code that runs with authority to create or manage systems must be as small as possible and written in a disciplined subset of C.
3. **Explicit authority and contracts** — No operation that can affect another domain or the host is permitted without an explicit, logged authorization decision.
4. **Least privilege by default** — Every system receives only the exact capabilities required for its declared purpose.
5. **Narrow terminal interface** — The only way in or out from the host terminal is through a small, carefully reviewed `l2` CLI/TUI and protocol. The client itself holds no raw authority.
6. **Evidence and audit** — All boundary crossings and authority grants are recorded in a form that supports later forensic analysis.

## Memory Safety in C

C is the implementation language for the substrate core. We treat memory safety as a first-class engineering problem:

- Strict coding rules (bounds-checked data structures, no unchecked pointer arithmetic in security-critical paths, explicit ownership).
- Mandatory static analysis on every change that touches the containment boundary or capability handling.
- Avoidance of undefined behavior; use of seL4's own verified runtime components where possible.
- Long-term hardware acceleration path: CHERI (or equivalent) to make spatial memory safety a hardware-enforced property for C code.

We do not claim memory safety equivalent to a memory-safe language in the initial implementation. The combination of seL4 isolation + rigorous process + future CHERI is the strategy.

## Alignment with NSA, CISA, and FBI Standards

l2 explicitly targets the security standards and best practices set forth by the NSA, CISA, and FBI through the following alignments (updated to strengthen compliance):

- **CISA Secure by Design and Secure by Default**: We follow the [CISA Secure by Design principles](https://www.cisa.gov/securebydesign) and the joint [Principles and Approaches for Security-by-Design and -Default](https://www.cisa.gov/sites/default/files/2023-04/principles_approaches_for_security-by-design-default_508_0.pdf) (CISA/NSA/FBI + international partners). This includes prioritizing memory safety, eliminating entire classes of vulnerabilities where possible, and building security into the architecture from the outset.
- **NSA Guidance**: Alignment with NSA recommendations on memory safety (e.g., preference for memory-safe languages or disciplined use of C with guards), network/substrate hardening (least privilege, minimal attack surface), and high-assurance system design. The prototype uses Linux namespaces with explicit authority to reduce attack surface.
- **CISA Cybersecurity Performance Goals (CPGs) and Best Practices**: Incorporation of key CPGs such as asset inventory (systems managed explicitly), vulnerability management (static analysis mandatory), and network segmentation principles adapted to intra-system isolation.
- **Joint CISA/NSA/FBI Advisories**: Avoidance of common misconfigurations (e.g., no ambient authority, explicit contracts only) as highlighted in joint guidance on top 10 misconfigurations and product security bad practices.
- **Prototype Hardening (Linux Namespaces Phase)**: Current isolation via `unshare`/`namespaces` is hardened per CISA/NSA container and host security guidance: full capability dropping, seccomp filters (planned/enhanced), strict policy enforcement for 'strict' mode (no unnecessary privileges, read-only where possible), and rejection of unsafe names/inputs. Future transition to seL4 will exceed current Linux-based controls.

These alignments ensure l2 not only meets but aims to exceed baseline expectations in the referenced standards. No formal certification is claimed yet, but the design supports auditable compliance.

## Reporting Security Issues

Vulnerabilities that affect the containment boundary or allow escape between systems or to the host are treated as critical. See the repository security policy or contact the maintainers.