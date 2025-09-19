/**
 * @file kprobe.h
 * @brief Traditional kernel hooks monitoring (kprobes, uprobes, tracepoint_probe_register).
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */

#ifndef KPROBE_H
#define KPROBE_H

#include <libvmi/events.h>
#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief Context for kprobe monitoring interrupt tasks.
 */
typedef struct kprobe_ctx {
  addr_t kaddr;        ///< Kernel address where breakpoint is set.
  uint8_t orig;        ///< Original byte at kaddr.
  char* symname;       ///< Symbol name at kaddr (allocated, must be freed).
  vmi_event_t ss_evt;  ///< Single-step event for re-arming breakpoint.
} kprobe_ctx_t;

/**
 * @brief Callback function for kprobe interrupt events.
 * 
 * @param vmi VMI instance
 * @param event Interrupt event
 * @return event_response_t Response code
 */
event_response_t event_kprobe_callback(vmi_instance_t vmi, vmi_event_t* event);

#endif  // KPROBE_H
