/*
 * core.h - Public interface of the l2 Core
 *
 * This header declares the services the core offers to other
 * components (future vectors, host shim, etc.).
 *
 * Nothing in this header may grant direct authority.
 * All operations must go through the core's capability-controlled interfaces.
 */

#pragma once

/* Future core services will be declared here, e.g.:
 *
 * l2_result_t l2_core_create_vector(...);
 * l2_result_t l2_core_revoke_vector(...);
 *
 * All such functions must be implemented following MEMORY_SAFETY.md.
 */
