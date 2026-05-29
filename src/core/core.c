/*
 * core.c
 *
 * l2 core pd - authority root
 */

#include <microkit.h>
#include "../common/safe.h"

void init(void) {
    microkit_dbg_puts("l2 core: alive\n");
}

void notified(microkit_channel ch) {
    (void)ch;
    microkit_dbg_puts("l2 core: notified\n");
}
