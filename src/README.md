# src

C implementation of the l2 substrate core.

## Model

Systems are created, populated, executed inside, queried, and destroyed on demand from the terminal.

All authority and boundary crossings go through the narrow `l2_sys_*` interface (see `core/sys.h`).

## Rules

- Public interface must stay tiny and stable.
- No leaks across system or host boundaries.
- Minimal core TCB at every layer.
- Rigorous memory safety discipline in security-critical paths (see CONTRIBUTING.md).
- Terminal CLI/TUI is the primary driver; keep the protocol narrow and auditable.

## Current Layout (minimal)

- `core/sys.h` — the complete public interface
- `core/` — core implementation
- `common/safe.*` — basic memory safety helpers

Everything else is either deprecated or will be removed as the narrow implementation stabilizes.

This is the focused Latticra substrate. Restraint applies here more than anywhere.
