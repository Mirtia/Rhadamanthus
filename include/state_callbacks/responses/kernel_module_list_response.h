/**
 * @file kernel_module_list_response.h
 * @brief Response structure and functions for kernel module list state analysis.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef KERNEL_MODULE_LIST_RESPONSE_H
#define KERNEL_MODULE_LIST_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (kernel_module_list_state_response)
 * ─────────────────────────────────────────────
 * {
 *   "state": "KERNEL_MODULE_LIST",
 *   "modules": [
 *     {
 *       "name": "ext4",
 *       "size": 1234567,
 *       "used_by_count": 0,
 *       "used_by": [],
 *       "state": "live",
 *       "offset": "0xffffffffc0000000",
 *       "module_base": "0xffffffffc0000000",
 *       "is_suspicious": false
 *     }
 *   ],
 *   "summary": {
 *     "total_modules": 10,
 *     "suspicious_modules": 0
 *   }
 * }
 */

/**
 * @brief Information about a kernel module.
 */
typedef struct kernel_module_info {
  char* name;              ///< Module name
  uint32_t size;           ///< Module size in bytes
  uint32_t used_by_count;  ///< Number of modules using this module
  GArray* used_by;         ///< Array of module names that use this module
  char* state;             ///< Module state (live, unloading, dead, etc.)
  char* offset;            ///< Memory offset (hex string)
  uint64_t module_base;    ///< Module base address
  bool is_suspicious;      ///< True if module appears suspicious
} kernel_module_info_t;

/**
 * @brief Summary information for kernel module list.
 */
typedef struct kernel_module_list_summary {
  uint32_t total_modules;       ///< Total number of modules found
  uint32_t suspicious_modules;  ///< Number of suspicious modules
} kernel_module_list_summary_t;

/**
 * @brief State data for kernel module list analysis.
 */
typedef struct kernel_module_list_state_data {
  GArray* modules;                       ///< Array of kernel_module_info_t
  kernel_module_list_summary_t summary;  ///< Summary information
} kernel_module_list_state_data_t;

/**
 * @brief Allocate and initialize a new kernel module list state data object.
 *
 * @return Pointer to a newly allocated kernel_module_list_state_data_t, or NULL on failure.
 */
kernel_module_list_state_data_t* kernel_module_list_state_data_new(void);

/**
 * @brief Free a kernel module list state data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void kernel_module_list_state_data_free(kernel_module_list_state_data_t* data);

/**
 * @brief Add a kernel module to the list.
 *
 * @param data The kernel module list state data object.
 * @param name Module name.
 * @param size Module size in bytes.
 * @param used_by_count Number of modules using this module.
 * @param used_by Array of module names that use this module (can be NULL).
 * @param state Module state.
 * @param offset Memory offset (hex string).
 * @param module_base Module base address.
 * @param is_suspicious Whether the module appears suspicious.
 */
void kernel_module_list_state_add_module(
    kernel_module_list_state_data_t* data, const char* name, uint32_t size,
    uint32_t used_by_count, GArray* used_by, const char* state,
    const char* offset, uint64_t module_base, bool is_suspicious);

/**
 * @brief Set the summary information.
 *
 * @param data The kernel module list state data object.
 * @param total_modules Total number of modules.
 * @param suspicious_modules Number of suspicious modules.
 */
void kernel_module_list_state_set_summary(kernel_module_list_state_data_t* data,
                                          uint32_t total_modules,
                                          uint32_t suspicious_modules);

/**
 * @brief Serialize a kernel module list state data object to JSON.
 *
 * @param data Pointer to the kernel module list state data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* kernel_module_list_state_data_to_json(
    const kernel_module_list_state_data_t* data);

#endif  // KERNEL_MODULE_LIST_RESPONSE_H
