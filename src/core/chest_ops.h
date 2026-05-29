/*
 * chest_ops.h - The minimal operations on a Treasure Chest
 *
 * This is the *entire* surface a developer interacts with for any given chest.
 * The substrate must enforce that nothing outside these operations is possible.
 *
 * See docs/TREASURE_CHEST_MODEL.md for the mental model.
 * See docs/CONTAINMENT_VECTOR_INTERFACE.md for the underlying security contract.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* Opaque handle to a chest. Never dereferenced by callers. */
typedef struct l2_chest *l2_chest_t;

/* Result type for chest operations */
typedef enum {
    L2_OK = 0,
    L2_ERR_INVALID,
    L2_ERR_NOAUTH,
    L2_ERR_NOSPACE,
    L2_ERR_NOTFOUND,
    L2_ERR_INTERNAL,
} l2_result_t;

/* Types of objects that can be put into a chest */
typedef enum {
    L2_OBJ_DATA,      /* Raw bytes */
    L2_OBJ_CREDENTIAL,/* Secret material */
    L2_OBJ_CODE,      /* Executable or script to run inside */
    L2_OBJ_MCP_SERVER,/* MCP server definition */
} l2_object_type_t;

/*
 * Create a new chest with the given policy.
 * The policy string is interpreted by the substrate (e.g. "strict", "mcp-only").
 */
l2_result_t l2_chest_create(const char *name, const char *policy, l2_chest_t *out);

/* Destroy a chest and all its contents. Irreversible. */
l2_result_t l2_chest_destroy(l2_chest_t chest);

/* Put an object into the chest.
 * The substrate must ensure the object cannot leak or be accessed
 * except through subsequent explicit get/exec operations.
 */
l2_result_t l2_chest_put(l2_chest_t chest,
                         const char *name,
                         l2_object_type_t type,
                         const void *data,
                         size_t size);

/* Retrieve an object from the chest (copy out). */
l2_result_t l2_chest_get(l2_chest_t chest,
                         const char *name,
                         void *buf,
                         size_t buf_size,
                         size_t *out_size);

/* Execute something inside the chest.
 * The substrate guarantees that the execution cannot affect
 * the host or other chests except through the returned result.
 */
l2_result_t l2_chest_exec(l2_chest_t chest,
                          const char *what,   /* name of code/MCP/etc inside */
                          const void *input,
                          size_t input_size,
                          void *output,
                          size_t output_size,
                          size_t *out_size);

/* List visible object names in the chest (subject to policy). */
l2_result_t l2_chest_list(l2_chest_t chest,
                          char *buf,
                          size_t buf_size,
                          size_t *out_count);

/* Revoke a previous grant or capability associated with this chest. */
l2_result_t l2_chest_revoke(l2_chest_t chest, const char *grant_id);
