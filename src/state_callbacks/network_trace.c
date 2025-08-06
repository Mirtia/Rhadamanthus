#include "state_callbacks/network_trace.h"
#include <log.h>

uint32_t state_network_trace_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_NETWORK_TRACE callback.");
    return VMI_SUCCESS;
}
