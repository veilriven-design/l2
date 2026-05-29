/*
 * safe.h - Foundational memory safety guards and types for l2
 *
 * All security-critical C code in l2 MUST include and use these utilities.
 * See docs/MEMORY_SAFETY.md for the full rules.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*
 * l2_size_t - Preferred size type for lengths that cross boundaries.
 * Always use this instead of raw size_t in public/core interfaces
 * when the value may be influenced by untrusted input.
 */
typedef size_t l2_size_t;

/*
 * L2_ARRAY_LEN - Compile-time array length helper.
 * Use instead of magic numbers or sizeof calculations in critical paths.
 */
#define L2_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * l2_bounds_check - Runtime bounds check helper.
 * Returns true if access at [offset, offset+len) is within [0, total).
 *
 * MUST be used before any access based on untrusted length.
 */
static inline bool
l2_bounds_check(l2_size_t offset, l2_size_t len, l2_size_t total)
{
    /* Careful overflow-safe check */
    if (len > total) {
        return false;
    }
    if (offset > total - len) {
        return false;
    }
    return true;
}

/*
 * l2_memcpy_safe - Bounds-checked memory copy.
 * Returns true on success, false on any violation.
 *
 * This is the only memcpy variant allowed in security-critical code.
 */
bool l2_memcpy_safe(void *restrict dst, l2_size_t dst_size,
                    const void *restrict src, l2_size_t src_size,
                    l2_size_t copy_len);

/*
 * l2_zero - Securely zero a buffer with explicit size.
 */
void l2_zero(void *buf, l2_size_t size);

/* TODO: Add more guards as the core develops:
 * - safe string handling
 * - capability wrapper types
 * - error propagation helpers that cannot leak state
 */
