# seL4 / Microkit Integration Plan

This document outlines the parallel track for the strong-isolation backend.

## Goal

The external interface (`l2` CLI + L2P protocol + `l2_sys_*`) must be identical whether the backend is the host prototype (namespaces today) or seL4.

## Approach

- Keep the core logic (capability management, system lifecycle, object put/get) in a portable C layer (`core/`).
- Host backend (`core/host.c`): uses Linux namespaces, seccomp, pivot_root, etc.
- seL4 backend: uses protection domains, capabilities, and IPC via Microkit.

## Current State (v0.5.0)

- L2P v1 E2E exercised on Linux: l2::Host (Linux backend impl of L2Core trait in src/lib.rs) + l2-core (host/core.rs) handle create/put/get/destroy/list + exec/revoke intent over narrow stdio protocol. External CLI + demos identical.
- C side: core/host.c implements portable l2_sys_* (with safe.h bounds/zero); src/core/core.c has PD skeleton + notified L2P stub + exercises narrow interface (v0.5 E2E progress: maps to seL4 caps/PDs in future while producing same North-Star evidence).
- Operational harden --apply + crypto + great-harden + audit --test close the loop on host; the same artifacts + commands will validate the seL4 PD once wired.
- `l2.system`, narrow L2P (docs/PROTOCOL.md), and policy protocols (great-harden etc) unchanged. "The external interface must remain the same".
- See also STATUS/ROADMAP for "mature Linux Host + credible seL4 traction".

## Next Steps (seL4 track)

1. Define the exact IPC interface between l2_core and the host shim on seL4.
2. Implement the L2P handler inside l2_core using seL4 primitives.
3. Map dynamic system creation to Microkit protection domain creation + capability delegation.
4. Ensure destroy path revokes all capabilities and reclaims memory.

The seL4 path is the long-term root of trust. The host prototype exists so we can dogfood the terminal experience and protocol *now* while the verified backend is developed.

See also: docs/PROTOCOL.md and core/sys.h.
