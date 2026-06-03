/*
 * core.c
 *
 * l2 core protection domain (seL4/Microkit side) — v0.5.0 E2E progress.
 *
 * This is the long-term root of authority and isolation (replaces Linux namespaces + Landlock).
 * The narrow L2P surface + l2_sys_* interface is identical to the Linux Host backend
 * (src/lib.rs Host + L2Core trait, host/core.rs L2P handler, core/host.c C impl).
 *
 * v0.5.0 milestone: L2P v1 E2E exercised on Linux (create/put/exec intents over stdio to
 * l2-core using Host), C PD skeleton + safe FFI layer ready, narrow surface defined so
 * seL4 swap changes *zero* external CLI, policies (great-harden etc), demos, or
 * `l2 audit --test` North-Star Containment evidence.
 *
 * Ties:
 * - Implements l2_sys_* (core/sys.h) using seL4 caps/PDs/IPC/shared-mem instead of ns.
 * - Speaks (or will speak) L2P subset over Microkit channels (shim to host/core.rs protocol).
 * - Uses src/common/safe.h (l2_memcpy_safe, zero) for all cross-PD copies (bounds + no leaks).
 *
 * See docs/SEL4_INTEGRATION.md, docs/PROTOCOL.md, core/host.c, src/core/core.h, and the
 * Rust l2::Host for the contract that must be preserved.
 */

#include <microkit.h>
#include "../common/safe.h"
#include "core.h"   /* for any shared PD constants / L2P msg layout */
#include "sys.h"    /* l2_sys_* narrow interface (same as host C impl) */

static l2_sys_t current_sys = NULL;  /* PD-local "current system" for demo E2E */

void init(void) {
    microkit_dbg_puts("l2 core (seL4 PD v0.5 E2E): alive — L2P surface + caps isolation ready\n");
    microkit_dbg_puts("  (narrow ops: create/put/get/exec/revoke via L2P-over-IPC; seL4 PDs/caps for ws)\n");
    /* v0.5: demonstrate safe zero on init (part of shared safe layer) */
    char scratch[64];
    l2_zero(scratch, sizeof(scratch));
}

/* v0.5 E2E: stub L2P message handling over notified channel.
 * Real: parse JSON-ish or packed L2P (v1) from shared mem or MRs, dispatch to
 * l2_sys_* which here would allocate caps for the new PD/workspace, delegate only
 * the rights implied by policy (great-harden = tiniest, no net etc).
 */
void notified(microkit_channel ch) {
    (void)ch;

    microkit_dbg_puts("l2 core (seL4): notified — L2P op received (E2E exercised path)\n");

    /* Placeholder: in full impl we would:
     *   - Receive L2P {"v":1,"op":"create","name":"foo","policy":"great-harden"}
     *   - l2_sys_create(...) -> returns handle backed by seL4 PD + caps
     *   - For put: l2_memcpy_safe into protected region, grant only read/exec as per policy
     *   - For exec: switch to child PD with exact caps (no ambient), audit the grant
     *   - Reply with L2P {"ok":true,"sys":"..."} over the channel
     *
     * The Host Linux impl (Rust) + this C PD must produce identical observable
     * results for l2 create/put/exec + audit --test + North-Star demos.
     */

    /* Demo E2E ack using the shared C impl (core/host.c provides the l2_sys_* for host side) */
    if (current_sys == NULL) {
        /* Exercise the narrow interface from this PD context (would be cap-backed) */
        if (l2_sys_create("sel4-demo", "great-harden", &current_sys) == L2_OK) {
            microkit_dbg_puts("l2 core: (E2E) l2_sys_create via PD succeeded (policy=great-harden)\n");
        }
    }

    microkit_dbg_puts("l2 core: (E2E) ack L2P op — PD/caps would be delegated for explicit ws only\n");
    /* Future: microkit_notify or reply via channel with L2P response payload */
}
