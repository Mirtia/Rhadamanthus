/**
 * @file netfilter_hook_write.h
 * @brief This file monitors netfilter hook registration events.
 * @version 0.0
 * @date 2025-08-24
 *
 * @copyright GNU Lesser General Public License v2.1
 *
 */
#ifndef NETFILTER_HOOK_WRITE_H
#define NETFILTER_HOOK_WRITE_H

#include <libvmi/events.h>

/**
 * @brief Context for the planted breakpoint on nf_register_net_hook(s).
 */
struct nf_bp_ctx_t {
  addr_t kaddr;         ///< Kernel VA of the function entry.
  uint8_t orig;         ///< Original first byte at entry.
  const char* symname;  ///< Symbol name.
  vmi_event_t ss_evt;   ///< One-shot SINGLESTEP event to re-arm INT3.
};

typedef struct nf_bp_ctx_t nf_bp_ctx_t;

/**
 * @brief Callback function for handling netfilter hook write events.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_netfilter_hook_write_callback(vmi_instance_t vmi,
                                                     vmi_event_t* event);

#endif  // NETFILTER_HOOK_WRITE_H