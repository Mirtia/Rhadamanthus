/**
 * @file ftrace_hook_response.h
 * @brief Response structure and functions for ftrace hook events.
 * @version 0.0
 * @date 2025-09-11
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef FTRACE_HOOK_RESPONSE_H
#define FTRACE_HOOK_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────────────
 * JSON Response Structure (ftrace_hook_response)
 * ─────────────────────────────────────────────────────
 * {
 *   "event": "FTRACE_HOOK",
 *   "vcpu_id": 0,
 *   "regs": {
 *     "rip": "0xfffff80000001234"
 *   },
 *   "memory": {
 *     "gla": "0xfffffe0000123456",
 *     "gpa": "0x0000000123400abc"
 *   }
 * }
 */

/**
 * @brief Event payload for a detected write to ftrace structures.
 *
 * This mirrors the allocation in event_ftrace_hook_callback().
 */
typedef struct ftrace_hook_data {
  uint32_t vcpu_id;  ///< vCPU that triggered the event.
  uint64_t rip;      ///< Guest RIP at the time of the event.
  uint64_t rsp;      ///< Guest RSP at the time of the event.
  uint64_t cr3;      ///< Guest CR3 at the time of the event.
  uint64_t rflags;   ///< Guest RFLAGS at the time of the event.
  uint64_t gla;      ///< Guest Linear Address involved in the access.
  uint64_t gpa;      ///< Guest Physical Address involved in the access.
  char* symname;     ///< Function name at RIP (allocated, must be freed).
} ftrace_hook_data_t;

/**
 * @brief Allocate and initialize a new ftrace hook data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The guest RIP.
 * @param rsp The guest RSP.
 * @param cr3 The guest CR3.
 * @param rflags The guest RFLAGS.
 * @param gla The guest linear address associated with the event.
 * @param gpa The guest physical address associated with the event.
 * @param symname The function name at RIP (will be duplicated).
 * @return Pointer to a newly allocated ftrace_hook_data_t, or NULL on failure.
 */
ftrace_hook_data_t* ftrace_hook_data_new(uint32_t vcpu_id, uint64_t rip,
                                         uint64_t rsp, uint64_t cr3,
                                         uint64_t rflags, uint64_t gla,
                                         uint64_t gpa, const char* symname);

/**
 * @brief Free a ftrace hook data object (safe on NULL).
 */
void ftrace_hook_data_free(ftrace_hook_data_t* data);

/**
 * @brief Serialize a ftrace hook data object to JSON.
 *
 * Produces the "vcpu_id", "regs", "memory" objects.
 *
 * @param data Pointer to the ftrace hook data object.
 * @return Newly allocated cJSON object, or NULL on failure.
 */
cJSON* ftrace_hook_data_to_json(const ftrace_hook_data_t* data);

#endif  // FTRACE_HOOK_RESPONSE_H
