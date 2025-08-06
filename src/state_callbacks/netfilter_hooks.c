#include "state_callbacks/netfilter_hooks.h"
#include <log.h>

uint32_t state_netfilter_hooks_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_NETFILTER_HOOKS callback.");
    return VMI_SUCCESS;
}
