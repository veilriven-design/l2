/*
 * example_vector.c
 *
 * demo workload inside system
 * only core-granted caps
 */

#include <microkit.h>

void init(void) {
    microkit_dbg_puts("l2 vector: started\n");
}

void notified(microkit_channel ch) {
    (void)ch;
}
