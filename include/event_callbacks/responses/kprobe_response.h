/**
 * @file kprobe_response.h
 * @brief Response structure and functions for kprobe events.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef KPROBE_RESPONSE_H
#define KPROBE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────────────
 * JSON Response Structure (kprobe_response)
 * ─────────────────────────────────────────────────────
 * {
 *   "event": "KPROBE",
 *   "vcpu_id": 0,
 *   "pid": 1234,
 *   "regs": {
 *     "rip": "0xfffff80000001234",
 *     "rsp": "0xfffffe0000123456",
 *     "cr3": "0x0000000123400abc"
 *   },
 *   "probe": {
 *     "address": "0xfffff80000001234",
 *     "function": "register_kprobe",
 *     "type": "kprobe",
 *     "target_symbol": "sys_open",
 *     "target_address": "0xfffff80000005678"
 *   }
 * }
 */

/**
 * @brief Event payload for a detected kprobe registration.
 */
typedef struct kprobe_data {
  uint32_t vcpu_id;  ///< vCPU that triggered the event.
  uint64_t rip;      ///< Guest RIP at the time of the event.
  uint64_t rsp;      ///< Guest RSP at the time of the event.
  uint64_t cr3;      ///< Guest CR3 at the time of the event.
  vmi_pid_t pid;     ///< Process ID (0 for kernel).
  addr_t kaddr;      ///< Kernel address where breakpoint was set.
  char* symname;     ///< Function name at kaddr (allocated, must be freed).
  char* probe_type;  ///< Type of probe (kprobe, uprobe, tracepoint).
  char*
      target_symbol;  ///< Target symbol being hooked (allocated, must be freed).
  addr_t target_addr;  ///< Target address being hooked.
} kprobe_data_t;

/**
 * @brief Allocate and initialize a new kprobe data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The guest RIP.
 * @param rsp The guest RSP.
 * @param cr3 The guest CR3.
 * @param pid The process ID.
 * @param kaddr The kernel address.
 * @param symname The function name (will be duplicated).
 * @param probe_type The probe type (will be duplicated).
 * @param target_symbol The target symbol (will be duplicated).
 * @param target_addr The target address.
 * @return Pointer to a newly allocated kprobe_data_t, or NULL on failure.
 */
kprobe_data_t* kprobe_data_new(uint32_t vcpu_id, uint64_t rip, uint64_t rsp,
                               uint64_t cr3, vmi_pid_t pid, addr_t kaddr,
                               const char* symname, const char* probe_type,
                               const char* target_symbol, addr_t target_addr);

/**
 * @brief Free a kprobe data object (safe on NULL).
 */
void kprobe_data_free(kprobe_data_t* data);

/**
 * @brief Serialize a kprobe data object to JSON.
 *
 * @param data Pointer to the kprobe data object.
 * @return Newly allocated cJSON object, or NULL on failure.
 */
cJSON* kprobe_data_to_json(const kprobe_data_t* data);

#endif  // KPROBE_RESPONSE_H
