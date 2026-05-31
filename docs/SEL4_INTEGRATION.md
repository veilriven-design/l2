# seL4 / Microkit Integration Plan

This document outlines the parallel track for the strong-isolation backend.

## Goal

The external interface (`l2` CLI + L2P protocol + `l2_sys_*`) must be identical whether the backend is the host prototype (namespaces today) or seL4.

## Approach

- Keep the core logic (capability management, system lifecycle, object put/get) in a portable C layer (`core/`).
- Host backend (`core/host.c`): uses Linux namespaces, seccomp, pivot_root, etc.
- seL4 backend: uses protection domains, capabilities, and IPC via Microkit.

## Current State

- `l2.system` updated to the narrow model (only l2_core is static).
- Host prototype (`src/main.rs`) already demonstrates real isolation via `unshare`.

## Next Steps (seL4 track)

1. Define the exact IPC interface between l2_core and the host shim on seL4.
2. Implement the L2P handler inside l2_core using seL4 primitives.
3. Map dynamic system creation to Microkit protection domain creation + capability delegation.
4. Ensure destroy path revokes all capabilities and reclaims memory.

The seL4 path is the long-term root of trust. The host prototype exists so we can dogfood the terminal experience and protocol *now* while the verified backend is developed.

See also: docs/PROTOCOL.md and core/sys.h.
