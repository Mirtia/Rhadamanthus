/**
 * @file syscall_table_response.h
 * @brief Response structure and functions for syscall table state analysis.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef SYSCALL_TABLE_RESPONSE_H
#define SYSCALL_TABLE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (syscall_table_state_response)
 * ─────────────────────────────────────────────
 * {
 *   "state": "SYSCALL_TABLE",
 *   "kernel_range": {
 *     "start": "0xffffffff81000000",
 *     "end": "0xffffffff82000000"
 *   },
 *   "syscall_table": {
 *     "address": "0xffffffff81e00000",
 *     "total_syscalls": 400
 *   },
 *   "syscalls": [
 *     {
 *       "index": 0,
 *       "name": "read",
 *       "address": "0xffffffff81050123",
 *       "is_hooked": false
 *     }
 *   ],
 *   "summary": {
 *     "total_hooked_syscalls": 0,
 *   }
 * }
 */

/**
 * @brief Information about a single syscall entry.
 */
typedef struct syscall_info {
  uint32_t index;    ///< Syscall index/number
  char* name;        ///< Syscall name (e.g., "read", "write")
  uint64_t address;  ///< Address of the syscall handler
  bool
      is_hooked;  ///< True if syscall appears to be hooked (outside kernel text)
} syscall_info_t;

/**
 * @brief State data for syscall table analysis.
 */
typedef struct syscall_table_state_data {
  uint64_t kernel_start;        ///< Start of kernel text section
  uint64_t kernel_end;          ///< End of kernel text section
  uint64_t syscall_table_addr;  ///< Address of the syscall table
  uint32_t total_syscalls;      ///< Total number of syscalls
  GArray* syscalls;             ///< Array of syscall_info_t
  uint32_t total_hooked;        ///< Total number of hooked syscalls detected
} syscall_table_state_data_t;

/**
 * @brief Allocate and initialize a new syscall table state data object.
 *
 * @return Pointer to a newly allocated syscall_table_state_data_t, or NULL on failure.
 */
syscall_table_state_data_t* syscall_table_state_data_new(void);

/**
 * @brief Free a syscall table state data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void syscall_table_state_data_free(syscall_table_state_data_t* data);

/**
 * @brief Set the kernel text section range.
 *
 * @param data The syscall table state data object.
 * @param kernel_start Start address of kernel text section.
 * @param kernel_end End address of kernel text section.
 */
void syscall_table_state_set_kernel_range(syscall_table_state_data_t* data,
                                          uint64_t kernel_start,
                                          uint64_t kernel_end);

/**
 * @brief Set the syscall table address and total count.
 *
 * @param data The syscall table state data object.
 * @param table_addr Address of the syscall table.
 * @param total_count Total number of syscalls.
 */
void syscall_table_state_set_table_info(syscall_table_state_data_t* data,
                                        uint64_t table_addr,
                                        uint32_t total_count);

/**
 * @brief Add syscall information.
 *
 * @param data The syscall table state data object.
 * @param index The syscall index.
 * @param name The syscall name.
 * @param address The syscall handler address.
 * @param is_hooked Whether the syscall appears to be hooked.
 */
void syscall_table_state_add_syscall(syscall_table_state_data_t* data,
                                     uint32_t index, const char* name,
                                     uint64_t address, bool is_hooked);

/**
 * @brief Set the summary information.
 *
 * @param data The syscall table state data object.
 * @param total_hooked Total number of hooked syscalls.
 */
void syscall_table_state_set_summary(syscall_table_state_data_t* data,
                                     uint32_t total_hooked);

/**
 * @brief Serialize a syscall table state data object to JSON.
 *
 * @param data Pointer to the syscall table state data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* syscall_table_state_data_to_json(const syscall_table_state_data_t* data);

#endif  // SYSCALL_TABLE_RESPONSE_H
