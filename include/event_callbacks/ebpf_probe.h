/**
  * @file ebpf_probe.h
  * @brief This file monitors eBPF probes.
  * @version 0.0
  * @date 2025-08-24
  *
  * @copyright GNU Lesser General Public License v2.1
  *
  */
#ifndef EBPF_PROBE_H
#define EBPF_PROBE_H

#include <libvmi/events.h>

/**
  * @brief Context structure for eBPF probe events.
  */
typedef struct {
  addr_t kaddr;         ///< Address where INT3 is planted.
  uint8_t orig;         ///< Original byte replaced by 0xCC.
  const char* symname;  ///< Symbol name.
  vmi_event_t ss_evt;   ///< One-shot SINGLESTEP event to re-arm INT3.
} ebpf_probe_ctx_t;

/**
  * @brief eBPF system call context.
  */
typedef struct {
  int cmd;             ///< BPF command (BPF_PROG_LOAD, BPF_PROG_ATTACH, etc.).
  uint32_t prog_type;  ///< eBPF program type.
  uint32_t insn_cnt;   ///< Instruction count.
  char prog_name[16];  ///< Program name.
  vmi_pid_t pid;       ///< Process ID.
  uint64_t timestamp;  ///< Event timestamp.
  addr_t user_attr;    ///< User-space bpf_attr pointer.
} ebpf_syscall_ctx_t;

/**
  * @brief Callback function for handling eBPF map update events.
  *
  * @param vmi The VMI instance.
  * @param event The event that triggered the callback.
  * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
  */

event_response_t event_ebpf_probe_callback(vmi_instance_t vmi,
                                           vmi_event_t* event);
#endif  // EBPF_PROBE_H
