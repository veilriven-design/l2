/*
 * example_vector.c
 *
 * simple example of code running inside an l2 system.
 * only has capabilities explicitly granted by the core.
 */

#include <microkit.h>

void init(void) {
    microkit_dbg_puts("l2 vector: started\n");
}

void notified(microkit_channel ch) {
    (void)ch;
}
