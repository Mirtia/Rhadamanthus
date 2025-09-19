/**
 * @file network_monitor.h
 * @brief This file monitors netfilter hook registration events.
 * @version 0.0
 * @date 2025-08-24
 *
 * @copyright GNU Lesser General Public License v2.1
 *
 */
#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include <libvmi/events.h>

/**
 * @brief Context for the planted breakpoint on network monitoring functions.
 */
struct nf_bp_ctx_t {
  addr_t kaddr;         ///< Kernel VA of the function entry.
  uint8_t orig;         ///< Original first byte at entry.
  const char* symname;  ///< Symbol name.
  vmi_event_t ss_evt;   ///< One-shot SINGLESTEP event to re-arm INT3.
};

typedef struct nf_bp_ctx_t nf_bp_ctx_t;

/**
 * @brief Callback function for handling comprehensive network monitoring events.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_network_monitor_callback(vmi_instance_t vmi,
                                                vmi_event_t* event);

#endif  // NETWORK_MONITOR_H