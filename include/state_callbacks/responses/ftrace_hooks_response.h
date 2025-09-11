/**
 * @file ftrace_hooks_response.h
 * @brief Response structure and functions for ftrace hooks state analysis.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef FTRACE_HOOKS_RESPONSE_H
#define FTRACE_HOOKS_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (ftrace_hooks_state_response)
 * ─────────────────────────────────────────────
 * {
 *   "state": "FTRACE_HOOKS",
 *   "loaded_programs": [
 *     {
 *       "id": 1,
 *       "type": "ftrace_hook",
 *       "name": "syscall_hook",
 *       "attach_type": "syscall",
 *       "function_addr": "0xffffffff81000000",
 *       "flags": "0x2000",
 *       "trampoline_addr": "0xffffffffc0000000",
 *       "saved_func_addr": "0xffffffff81000000",
 *       "is_suspicious": true,
 *       "hook_reason": "IPMODIFY flag detected"
 *     }
 *   ],
 *   "attachment_points": {
 *     "syscall": [1, 2],
 *     "kprobe": [3, 4]
 *   },
 *   "summary": {
 *     "total_hooks": 5,
 *     "suspicious_hooks": 2,
 *     "global_ftrace_enabled": true,
 *     "commonly_hooked_syscalls": 3,
 *     "hooks_by_type": {
 *       "syscall": 2,
 *       "kprobe": 3
 *     }
 *   }
 * }
 */

/**
 * @brief Information about a ftrace hook/program.
 */
typedef struct ftrace_hook_info {
  uint32_t id;               ///< Hook ID/sequence number
  char* type;                ///< Hook type (ftrace_hook, kprobe, etc.)
  char* name;                ///< Hook name or function name
  char* attach_type;         ///< Attachment type (syscall, kprobe, etc.)
  uint64_t function_addr;    ///< Hook function address
  char* flags;               ///< Ftrace flags (hex string)
  uint64_t trampoline_addr;  ///< Trampoline address
  uint64_t saved_func_addr;  ///< Original function address
  bool is_suspicious;        ///< True if hook appears suspicious
  char* hook_reason;         ///< Reason for suspicion
} ftrace_hook_info_t;

/**
 * @brief Summary information for ftrace hooks analysis.
 */
typedef struct ftrace_hooks_summary {
  uint32_t total_hooks;               ///< Total number of hooks found
  uint32_t suspicious_hooks;          ///< Number of suspicious hooks
  bool global_ftrace_enabled;         ///< Whether ftrace is globally enabled
  uint32_t commonly_hooked_syscalls;  ///< Number of commonly hooked syscalls
  GHashTable* hooks_by_type;          ///< Hash table of hook counts by type
} ftrace_hooks_summary_t;

/**
 * @brief State data for ftrace hooks analysis.
 */
typedef struct ftrace_hooks_state_data {
  GArray* loaded_programs;         ///< Array of ftrace_hook_info_t
  GHashTable* attachment_points;   ///< Hash table of attachment points by type
  ftrace_hooks_summary_t summary;  ///< Summary information
} ftrace_hooks_state_data_t;

/**
 * @brief Allocate and initialize a new ftrace hooks state data object.
 *
 * @return Pointer to a newly allocated ftrace_hooks_state_data_t, or NULL on failure.
 */
ftrace_hooks_state_data_t* ftrace_hooks_state_data_new(void);

/**
 * @brief Free a ftrace hooks state data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void ftrace_hooks_state_data_free(ftrace_hooks_state_data_t* data);

/**
 * @brief Add a ftrace hook to the list.
 *
 * @param data The ftrace hooks state data object.
 * @param id Hook ID/sequence number.
 * @param type Hook type.
 * @param name Hook name or function name.
 * @param attach_type Attachment type.
 * @param function_addr Hook function address.
 * @param flags Ftrace flags.
 * @param trampoline_addr Trampoline address.
 * @param saved_func_addr Original function address.
 * @param is_suspicious Whether the hook appears suspicious.
 * @param hook_reason Reason for suspicion (can be NULL).
 */
void ftrace_hooks_state_add_hook(ftrace_hooks_state_data_t* data, uint32_t id,
                                 const char* type, const char* name,
                                 const char* attach_type,
                                 uint64_t function_addr, const char* flags,
                                 uint64_t trampoline_addr,
                                 uint64_t saved_func_addr, bool is_suspicious,
                                 const char* hook_reason);

/**
 * @brief Add an attachment point to the attachment points hash table.
 *
 * @param data The ftrace hooks state data object.
 * @param attach_type Attachment type.
 * @param hook_id Hook ID to add.
 */
void ftrace_hooks_state_add_attachment_point(ftrace_hooks_state_data_t* data,
                                             const char* attach_type,
                                             uint32_t hook_id);

/**
 * @brief Set the summary information.
 *
 * @param data The ftrace hooks state data object.
 * @param total_hooks Total number of hooks.
 * @param suspicious_hooks Number of suspicious hooks.
 * @param global_ftrace_enabled Whether ftrace is globally enabled.
 * @param commonly_hooked_syscalls Number of commonly hooked syscalls.
 */
void ftrace_hooks_state_set_summary(ftrace_hooks_state_data_t* data,
                                    uint32_t total_hooks,
                                    uint32_t suspicious_hooks,
                                    bool global_ftrace_enabled,
                                    uint32_t commonly_hooked_syscalls);

/**
 * @brief Serialize a ftrace hooks state data object to JSON.
 *
 * @param data Pointer to the ftrace hooks state data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* ftrace_hooks_state_data_to_json(const ftrace_hooks_state_data_t* data);

#endif  // FTRACE_HOOKS_RESPONSE_H
