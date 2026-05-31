# Contributing to l2

**l2 is the narrow Latticra substrate.** Precision, restraint, and terminal focus matter more than velocity or features.

## The Mission (non-negotiable)

Every change must serve this:

> A minimal high-assurance system for creating, using, and destroying strongly isolated execution contexts on demand from the terminal — with a tiny public surface and total cleanup on destroy.

## Hard Rules

- **Prefer deletion.** If a change can be achieved by removing code, documentation, or concepts instead of adding them, do that.
- **Terminal experience is sacred.** Changes that degrade the direct, precise, scriptable CLI/TUI feel will be rejected.
- **Boundary and authority changes require two-person review.** This includes anything in the `l2_sys_*` surface, the host protocol, capability handling, or the core.
- **No scope creep.** New documents, layers, models, or frameworks that are not strictly required for the substrate + terminal driver are out of scope.

## Code Style (C)

- Extreme discipline in security-critical paths.
- Bounds-checked everything. No unchecked pointer arithmetic or untrusted sizes in the core.
- Static analysis clean (warnings as errors) on all changes touching authority or boundaries.
- Follow seL4 conventions where they do not conflict with our stricter safety rules.

## Documentation

One tight, precise document or section is vastly preferred over many vague ones. The goal is clarity for implementers and reviewers, not academic breadth.

## Security & Threat Model

See `SECURITY.md`. Anything that could weaken containment or allow escape between systems or to the host is treated as critical.

## Getting Started

The best early contributions are:
- Improving the terminal CLI/TUI experience and its design document
- Implementing narrow, well-specified pieces of the `l2_sys_*` surface
- Host backend work that keeps the TCB small
- Brutal pruning of anything that no longer serves the narrow charter

If your proposed change grows the conceptual surface area of l2, it is probably the wrong change.
