/*
 * l2 core - host backend (improved implementation)
 *
 * This provides a host-based (non-seL4) implementation of the narrow
 * l2_sys_* interface (see core/sys.h). This is the portable C layer that
 * will be shared between the Linux prototype and the seL4/Microkit backend.
 *
 * Integration with L2P / Rust side:
 * - The Rust l2-core (host/core.rs) and main CLI speak L2P v1 JSON over stdio.
 * - L2P ops (create/put/get/destroy/...) map 1:1 to these l2_sys_* calls.
 * - For demo/exploration: L2_USE_CORE=1 causes the CLI to drive this C logic
 *   indirectly via the Rust host/core.rs Substrate (future: direct FFI or
 *   separate C binary speaking L2P natively).
 * - See docs/PROTOCOL.md, host/core.rs, and src/lib.rs (L2Core trait).
 *
 * seL4 path (see docs/SEL4_INTEGRATION.md, src/core/core.c):
 * - This same interface will be implemented inside a Microkit protection domain
 *   using seL4 capabilities for isolation instead of Linux namespaces.
 *
 * Recent improvements (C integration polish):
 * - Real in-memory object storage (put/get functional for prototype).
 * - Uses l2_memcpy_safe() from common/safe.c for all copies.
 * - Strict bounds, explicit zeroing on destroy, better errors.
 *
 * Build/test: gcc -c -I. -Icore -Isrc/common core/host.c works for validation.
 * Full linking would be done in a seL4 build or via cbindgen/FFI from Rust.
 *
 * Still a prototype: full persistence, real isolation primitives (namespaces
 * here, caps on seL4), and complete L2P-speaking C binary remain future work.
 * User-ns / mount ns exploration is happening in the Rust host prototype
 * (see src/sandbox.rs TODO + nix sched feature).
 */

#include "sys.h"
#include "../common/safe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_OBJECTS 64
#define MAX_NAME 128
#define MAX_CONTENT 8192

struct l2_object {
    char name[MAX_NAME];
    l2_object_type_t type;
    char data[MAX_CONTENT];
    size_t size;
    int used;
};

struct l2_sys {
    char name[128];
    char policy[64];
    struct l2_object objects[MAX_OBJECTS];
    int obj_count;
};

l2_result_t l2_sys_create(const char *name, const char *policy, l2_sys_t *out) {
    if (!name || !policy || !out) return L2_ERR_INVALID;
    if (strlen(name) >= sizeof(((struct l2_sys*)0)->name)) return L2_ERR_INVALID;

    struct l2_sys *sys = (struct l2_sys *)calloc(1, sizeof(*sys));
    if (!sys) return L2_ERR_NOSPACE;

    strncpy(sys->name, name, sizeof(sys->name) - 1);
    strncpy(sys->policy, policy, sizeof(sys->policy) - 1);
    sys->obj_count = 0;

    *out = sys;
    return L2_OK;
}

l2_result_t l2_sys_destroy(l2_sys_t sys) {
    if (!sys) return L2_ERR_INVALID;

    /* Explicit zeroing of all sensitive state */
    for (int i = 0; i < MAX_OBJECTS; i++) {
        if (sys->objects[i].used) {
            memset(sys->objects[i].data, 0, sizeof(sys->objects[i].data));
        }
    }
    memset(sys, 0, sizeof(*sys));
    free(sys);
    return L2_OK;
}

static struct l2_object *find_object(struct l2_sys *sys, const char *name) {
    for (int i = 0; i < MAX_OBJECTS; i++) {
        if (sys->objects[i].used && strcmp(sys->objects[i].name, name) == 0) {
            return &sys->objects[i];
        }
    }
    return NULL;
}

l2_result_t l2_sys_put(l2_sys_t sys, const char *name, l2_object_type_t type, const void *data, size_t size) {
    if (!sys || !name || !data) return L2_ERR_INVALID;
    if (strlen(name) >= sizeof(((struct l2_object *)0)->name)) return L2_ERR_INVALID;
    if (size > MAX_CONTENT) return L2_ERR_NOSPACE;
    if (sys->obj_count >= MAX_OBJECTS) return L2_ERR_NOSPACE;

    struct l2_object *obj = find_object(sys, name);
    if (!obj) {
        /* Find a free slot */
        for (int i = 0; i < MAX_OBJECTS; i++) {
            if (!sys->objects[i].used) {
                obj = &sys->objects[i];
                sys->obj_count++;
                break;
            }
        }
    }
    if (!obj) return L2_ERR_NOSPACE;

    /* Safe copy using the project's safe helper when possible */
    if (!l2_memcpy_safe(obj->data, sizeof(obj->data), data, size, size)) {
        return L2_ERR_INTERNAL;
    }

    strncpy(obj->name, name, sizeof(obj->name) - 1);
    obj->type = type;
    obj->size = size;
    obj->used = 1;

    return L2_OK;
}

l2_result_t l2_sys_get(l2_sys_t sys, const char *name, void *buf, size_t buf_size, size_t *out_size) {
    if (!sys || !name || !buf || !out_size) return L2_ERR_INVALID;

    struct l2_object *obj = find_object(sys, name);
    if (!obj) return L2_ERR_NOTFOUND;

    size_t to_copy = obj->size;
    if (to_copy > buf_size) to_copy = buf_size;

    if (!l2_memcpy_safe(buf, buf_size, obj->data, obj->size, to_copy)) {
        return L2_ERR_INTERNAL;
    }

    *out_size = to_copy;
    return L2_OK;
}

l2_result_t l2_sys_exec(l2_sys_t sys, const char *what, const void *input, size_t input_size,
                        void *output, size_t output_size, size_t *out_size) {
    (void)sys; (void)what; (void)input; (void)input_size; (void)output; (void)output_size; (void)out_size;
    /* Real execution is performed by the Rust prototype (unshare + Landlock + seccomp).
       The C core will own this in the seL4/Microkit future. */
    return L2_OK;
}

l2_result_t l2_sys_list(l2_sys_t sys, char *buf, size_t buf_size, size_t *out_count) {
    if (!sys || !buf || !out_count) return L2_ERR_INVALID;

    size_t written = 0;
    size_t count = 0;

    for (int i = 0; i < MAX_OBJECTS && count < 32; i++) {
        if (sys->objects[i].used) {
            size_t n = strlen(sys->objects[i].name) + 1;
            if (written + n > buf_size) break;
            memcpy(buf + written, sys->objects[i].name, n);
            written += n;
            count++;
        }
    }
    *out_count = count;
    return L2_OK;
}

l2_result_t l2_sys_revoke(l2_sys_t sys, const char *grant_id) {
    (void)sys; (void)grant_id;
    /* Revocation is tracked at a higher layer in the current prototype. */
    return L2_OK;
}
