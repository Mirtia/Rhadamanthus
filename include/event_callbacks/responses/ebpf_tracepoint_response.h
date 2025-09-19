/**
 * @file ebpf_tracepoint_response.h
 * @brief Response structure and functions for eBPF tracepoint events.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef EBPF_TRACEPOINT_RESPONSE_H
#define EBPF_TRACEPOINT_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────────────
 * JSON Response Structure (ebpf_tracepoint_response)
 * ─────────────────────────────────────────────────────
 * {
 *   "event": "EBPF_TRACEPOINT",
 *   "vcpu_id": 0,
 *   "pid": 1234,
 *   "regs": {
 *     "rip": "0xfffff80000001234",
 *     "rsp": "0xfffffe0000123456",
 *     "cr3": "0x0000000123400abc"
 *   },
 *   "program": {
 *     "address": "0xfffff80000001234",
 *     "function": "bpf_prog_attach",
 *     "type": "bpf_prog",
 *     "attach_type": 1,
 *     "tracepoint_name": "sys_enter_open"
 *   }
 * }
 */

/**
 * @brief Event payload for a detected eBPF tracepoint program.
 */
typedef struct ebpf_tracepoint_data {
  uint32_t vcpu_id;      ///< vCPU that triggered the event.
  uint64_t rip;          ///< Guest RIP at the time of the event.
  uint64_t rsp;          ///< Guest RSP at the time of the event.
  uint64_t cr3;          ///< Guest CR3 at the time of the event.
  vmi_pid_t pid;         ///< Process ID (0 for kernel).
  addr_t kaddr;          ///< Kernel address where breakpoint was set.
  char* symname;         ///< Function name at kaddr (allocated, must be freed).
  char* program_type;    ///< Type of program (bpf_prog, tracepoint, fmod_ret).
  uint32_t attach_type;  ///< eBPF attach type.
  char* tracepoint_name;  ///< Tracepoint name (allocated, must be freed).
} ebpf_tracepoint_data_t;

/**
 * @brief Allocate and initialize a new eBPF tracepoint data object.
 *
 * @param vcpu_id The vCPU identifier.
 * @param rip The guest RIP.
 * @param rsp The guest RSP.
 * @param cr3 The guest CR3.
 * @param pid The process ID.
 * @param kaddr The kernel address.
 * @param symname The function name (will be duplicated).
 * @param program_type The program type (will be duplicated).
 * @param attach_type The attach type.
 * @param tracepoint_name The tracepoint name (will be duplicated).
 * @return Pointer to a newly allocated ebpf_tracepoint_data_t, or NULL on failure.
 */
ebpf_tracepoint_data_t* ebpf_tracepoint_data_new(
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3, vmi_pid_t pid,
    addr_t kaddr, const char* symname, const char* program_type,
    uint32_t attach_type, const char* tracepoint_name);

/**
 * @brief Free an eBPF tracepoint data object (safe on NULL).
 */
void ebpf_tracepoint_data_free(ebpf_tracepoint_data_t* data);

/**
 * @brief Serialize an eBPF tracepoint data object to JSON.
 *
 * @param data Pointer to the eBPF tracepoint data object.
 * @return Newly allocated cJSON object, or NULL on failure.
 */
cJSON* ebpf_tracepoint_data_to_json(const ebpf_tracepoint_data_t* data);

#endif  // EBPF_TRACEPOINT_RESPONSE_H
