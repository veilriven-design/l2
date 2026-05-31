/*
 * l2 core - host backend skeleton (initial implementation)
 *
 * This provides a host-based (non-seL4) implementation of the narrow
 * l2_sys_* interface for development and as a reference.
 *
 * Rules (enforced):
 * - All buffers carry explicit sizes
 * - No unchecked pointer arithmetic in security paths
 * - Explicit zeroing of sensitive data on destroy
 * - Every authority grant is logged/auditable
 */

#include "sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct l2_sys {
    char name[128];
    char policy[64];
    /* In real version: capability lists, memory regions, etc. */
};

l2_result_t l2_sys_create(const char *name, const char *policy, l2_sys_t *out) {
    if (!name || !policy || !out) return L2_ERR_INVALID;

    struct l2_sys *sys = (struct l2_sys *)calloc(1, sizeof(*sys));
    if (!sys) return L2_ERR_NOSPACE;

    strncpy(sys->name, name, sizeof(sys->name) - 1);
    strncpy(sys->policy, policy, sizeof(sys->policy) - 1);

    *out = sys;
    /* TODO: integrate with host isolation primitives (namespaces, seccomp) */
    return L2_OK;
}

l2_result_t l2_sys_destroy(l2_sys_t sys) {
    if (!sys) return L2_ERR_INVALID;
    /* Explicit zero sensitive state */
    memset(sys, 0, sizeof(*sys));
    free(sys);
    return L2_OK;
}

/* Stubs for remaining functions - real implementations will follow */
l2_result_t l2_sys_put(l2_sys_t sys, const char *name, l2_object_type_t type, const void *data, size_t size) {
    (void)sys; (void)name; (void)type; (void)data; (void)size;
    return L2_OK; /* TODO */
}

l2_result_t l2_sys_get(l2_sys_t sys, const char *name, void *buf, size_t buf_size, size_t *out_size) {
    (void)sys; (void)name; (void)buf; (void)buf_size; (void)out_size;
    return L2_OK; /* TODO */
}

l2_result_t l2_sys_exec(l2_sys_t sys, const char *what, const void *input, size_t input_size,
                        void *output, size_t output_size, size_t *out_size) {
    (void)sys; (void)what; (void)input; (void)input_size; (void)output; (void)output_size; (void)out_size;
    return L2_OK; /* Real work now happens via the Rust host prototype using unshare */
}

l2_result_t l2_sys_list(l2_sys_t sys, char *buf, size_t buf_size, size_t *out_count) {
    (void)sys; (void)buf; (void)buf_size; (void)out_count;
    return L2_OK;
}

l2_result_t l2_sys_revoke(l2_sys_t sys, const char *grant_id) {
    (void)sys; (void)grant_id;
    return L2_OK;
}
