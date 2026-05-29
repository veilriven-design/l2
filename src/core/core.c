/*
 * core.c
 *
 * the actual l2 core protection domain. this is where authority comes from.
 * for now it's mostly a stub that will grow into the real thing.
 */

#include <microkit.h>
#include "../common/safe.h"

void
init(void)
{
    microkit_dbg_puts("l2 core: alive\n");
}

void
notified(microkit_channel ch)
{
    (void)ch;
    microkit_dbg_puts("l2 core: got a notification\n");
}
