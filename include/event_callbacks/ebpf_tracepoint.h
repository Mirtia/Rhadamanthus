/**
 * @file ebpf_tracepoint.h
 * @brief eBPF tracepoint programs monitoring (bpf_prog_attach, fmod_ret, etc.).
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */

#ifndef EBPF_TRACEPOINT_H
#define EBPF_TRACEPOINT_H

#include <libvmi/events.h>
#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief Context for eBPF tracepoint monitoring interrupt tasks.
 */
typedef struct ebpf_tracepoint_ctx {
  addr_t kaddr;        ///< Kernel address where breakpoint is set.
  uint8_t orig;        ///< Original byte at kaddr.
  char* symname;       ///< Symbol name at kaddr (allocated, must be freed).
  vmi_event_t ss_evt;  ///< Single-step event for re-arming breakpoint.
} ebpf_tracepoint_ctx_t;

/**
 * @brief Callback function for eBPF tracepoint interrupt events.
 * 
 * @param vmi VMI instance
 * @param event Interrupt event
 * @return event_response_t Response code
 */
event_response_t event_ebpf_tracepoint_callback(vmi_instance_t vmi,
                                                vmi_event_t* event);

#endif  // EBPF_TRACEPOINT_H
