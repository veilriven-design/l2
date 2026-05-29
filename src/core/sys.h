/*
 * sys.h
 *
 * full public interface for l2 system
 * only these calls allowed
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct l2_sys *l2_sys_t;

typedef enum {
    L2_OK = 0,
    L2_ERR_INVALID,
    L2_ERR_NOAUTH,
    L2_ERR_NOSPACE,
    L2_ERR_NOTFOUND,
    L2_ERR_INTERNAL,
} l2_result_t;

typedef enum {
    L2_OBJ_DATA,
    L2_OBJ_CREDENTIAL,
    L2_OBJ_CODE,
    L2_OBJ_MCP_SERVER,
} l2_object_type_t;

l2_result_t l2_sys_create(const char *name, const char *policy, l2_sys_t *out);
l2_result_t l2_sys_destroy(l2_sys_t sys);
l2_result_t l2_sys_put(l2_sys_t sys, const char *name, l2_object_type_t type, const void *data, size_t size);
l2_result_t l2_sys_get(l2_sys_t sys, const char *name, void *buf, size_t buf_size, size_t *out_size);
l2_result_t l2_sys_exec(l2_sys_t sys, const char *what, const void *input, size_t input_size, void *output, size_t output_size, size_t *out_size);
l2_result_t l2_sys_list(l2_sys_t sys, char *buf, size_t buf_size, size_t *out_count);
l2_result_t l2_sys_revoke(l2_sys_t sys, const char *grant_id);
