/*
 * example_vector.c - Minimal example of code that runs inside a Containment Vector
 *
 * This demonstrates the separation:
 * - This code only has the capabilities the core explicitly gave it.
 * - It has no ability to create other vectors or escape its containment.
 *
 * In a real system this would be replaced by actual workload code
 * (e.g. an MCP server) that only sees mediated interfaces.
 */

#include <microkit.h>

void
init(void)
{
    microkit_dbg_puts("l2 vector: example workload started\n");
}

void
notified(microkit_channel ch)
{
    (void)ch;
    /* Vectors only react to notifications on channels the core granted them */
}
