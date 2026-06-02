/*
 * core.c
 *
 * l2 core protection domain (seL4/Microkit side).
 * This is the long-term root of authority and isolation (replaces Linux namespaces).
 *
 * Ties to C integration / L2P:
 * - Implements (or will implement) the l2_sys_* interface from core/sys.h.
 * - Will speak L2P (or a thin shim) to the host side (see host/core.rs and docs/PROTOCOL.md).
 * - Uses seL4 capabilities, protection domains, and IPC instead of unshare/Landlock/seccomp.
 *
 * Current state: Minimal skeleton using Microkit (init + notified).
 * Future: Map create/destroy/put/get/exec to PD creation, cap delegation, shared memory
 * via safe.c helpers, etc. See docs/SEL4_INTEGRATION.md and core/host.c (host backend reference).
 *
 * Polish note: Uses safe.h include for future memory-safe ops (e.g., l2_memcpy_safe
 * when copying objects or messages across protection domains).
 */

#include <microkit.h>
#include "../common/safe.h"

void init(void) {
    microkit_dbg_puts("l2 core (seL4 PD): alive - ready for L2P + capability-based isolation\n");
}

void notified(microkit_channel ch) {
    (void)ch;
    microkit_dbg_puts("l2 core: notified (IPC or L2P message path placeholder)\n");
    /* Future: dispatch L2P-style requests here using seL4 primitives */
}
