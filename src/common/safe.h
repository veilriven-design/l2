/*
 * safe.h
 *
 * basic guards we actually use so we don't do stupid shit in c.
 * include this in anything that touches untrusted sizes or crosses boundaries.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef size_t l2_size_t;

#define L2_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

/* safe bounds check, tries to avoid overflow mistakes */
static inline bool
l2_bounds_check(l2_size_t offset, l2_size_t len, l2_size_t total)
{
    if (len > total) return false;
    if (offset > total - len) return false;
    return true;
}

/* the only memcpy you're allowed to use in critical code */
bool l2_memcpy_safe(void *restrict dst, l2_size_t dst_size,
                    const void *restrict src, l2_size_t src_size,
                    l2_size_t copy_len);

void l2_zero(void *buf, l2_size_t size);
