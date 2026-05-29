/*
 * safe.c
 *
 * guard impls
 */

#include "safe.h"

#include <string.h>

bool l2_memcpy_safe(void *restrict dst, l2_size_t dst_size, const void *restrict src, l2_size_t src_size, l2_size_t copy_len) {
    if (!dst || !src) return false;
    if (!l2_bounds_check(0, copy_len, dst_size)) return false;
    if (!l2_bounds_check(0, copy_len, src_size)) return false;
    memcpy(dst, src, copy_len);
    return true;
}

void l2_zero(void *buf, l2_size_t size) {
    if (!buf || size == 0) return;
    memset(buf, 0, size);
}
