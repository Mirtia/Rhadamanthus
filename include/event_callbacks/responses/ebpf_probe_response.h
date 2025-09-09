/**
 * @file ebpf_probe_response.h
 * @brief Response structure and functions for eBPF probe events
 * @version 0.0
 * @date 2025-09-09
 * 
 * @copyright Copyright (c) 2025
 */

#ifndef EBPF_PROBE_RESPONSE_H
#define EBPF_PROBE_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib.h>
#include <libvmi/libvmi.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Structure to hold eBPF probe event data
 */
typedef struct {
  uint32_t vcpu_id;  ///< Virtual CPU identifier where the event occurred
  uint64_t rip;      ///< Instruction pointer register value
  uint64_t rsp;      ///< Stack pointer register value
  uint64_t cr3;      ///< Control register 3 value (page table base)
  vmi_pid_t pid;     ///< Process identifier (0 if unknown)
  addr_t kaddr;      ///< Kernel address where the probe was inserted
  char* symname;     ///< Function name being probed (can be NULL)
  char* probe_type;  ///< Type of probe (kprobe, uprobe, bpf_prog, tracepoint)
  char*
      target_symbol;  ///< Target symbol name for kprobe/kretprobe (can be NULL)
  addr_t target_addr;  ///< Target address for kprobe/kretprobe (0 if unknown)
  uint32_t
      attach_type;  ///< BPF attach type for bpf_prog probes (0 if not applicable)
  char*
      tracepoint_name;  ///< Tracepoint name for tracepoint probes (can be NULL)
} ebpf_probe_data_t;

/**
 * @brief Create a new eBPF probe data structure
 * 
 * @param vcpu_id Virtual CPU identifier
 * @param rip Instruction pointer register value
 * @param rsp Stack pointer register value
 * @param cr3 Control register 3 value
 * @param pid Process identifier
 * @param kaddr Kernel address of the probe
 * @param symname Symbol name being probed
 * @param probe_type Type of probe (kprobe, uprobe, bpf_prog, etc.)
 * @param target_symbol Target symbol name (can be NULL)
 * @param target_addr Target address (can be 0)
 * @param attach_type BPF attach type (can be 0)
 * @param tracepoint_name Tracepoint name (can be NULL)
 * @return ebpf_probe_data_t* Pointer to allocated structure or NULL on failure
 */
ebpf_probe_data_t* ebpf_probe_data_new(
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3, vmi_pid_t pid,
    addr_t kaddr, const char* symname, const char* probe_type,
    const char* target_symbol, addr_t target_addr, uint32_t attach_type,
    const char* tracepoint_name);

/**
 * @brief Free eBPF probe data structure
 * 
 * @param data Pointer to the structure to free
 */
void ebpf_probe_data_free(ebpf_probe_data_t* data);

/**
 * @brief Convert eBPF probe data to JSON representation
 * 
 * @param data Pointer to the data structure
 * @return cJSON* JSON object or NULL on failure
 */
cJSON* ebpf_probe_data_to_json(const ebpf_probe_data_t* data);

#endif  // EBPF_PROBE_RESPONSE_H