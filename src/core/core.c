/*
 * core.c - l2 Core Protection Domain
 *
 * This is the root of the l2 userland TCB.
 * It is responsible for creating and managing all Containment Vectors.
 *
 * Rules:
 * - Must follow docs/MEMORY_SAFETY.md strictly
 * - Must only use capabilities it is explicitly given at boot
 * - All authority it grants to vectors must be auditable and revocable
 */

#include <microkit.h>
#include "../common/safe.h"

/*
 * Temporary placeholder.
 * Real core will initialize the vector management structures,
 * set up the host communication channel, and prepare to create vectors.
 */
void
init(void)
{
    /*
     * In a real system we would here:
     * - Receive and record our initial capabilities
     * - Set up any static vectors defined in the system description
     * - Initialize audit/evidence structures
     */

    microkit_dbg_puts("l2 core: initialized\n");
}

void
notified(microkit_channel ch)
{
    /*
     * Future: Handle requests from the host terminal shim
     * or from child vectors via mediated channels.
     */
    (void)ch;
    microkit_dbg_puts("l2 core: received notification\n");
}
