/*
 * safe.h
 *
 * Basic memory safety guards (bounds + zero) used by Linux Host (core/host.c + Rust)
 * and seL4 PD (src/core/core.c). Part of the v0.5.0 narrow L2P surface that allows
 * backend swap (namespaces -> caps) with no change to l2 CLI, policies, or demos.
 *
 * Draws from open-source CHERI (capability hardware: bounds-checked pointers with perms;
 * open CheriBSD, CHERI Clang) and seL4 (verified caps + safe runtime). Software fallback
 * for spatial safety in C subset. Combined with Landlock/seccomp for full OpenBSD-pledge/unveil
 * + Capsicum/Genode cap model on host.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef size_t l2_size_t;

#define L2_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

static inline bool l2_bounds_check(l2_size_t offset, l2_size_t len, l2_size_t total) {
    if (len > total) return false;
    if (offset > total - len) return false;
    return true;
}

bool l2_memcpy_safe(void *restrict dst, l2_size_t dst_size, const void *restrict src, l2_size_t src_size, l2_size_t copy_len);
void l2_zero(void *buf, l2_size_t size);
