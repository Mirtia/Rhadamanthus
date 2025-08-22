#include "state_callbacks/ftrace_hooks.h"
#include <log.h>

uint32_t state_ftrace_hooks_callback(vmi_instance_t vmi, void* context) {
    (void)context;
    
    log_info("Executing STATE_FTRACE_HOOKS callback.");
    return VMI_SUCCESS;
}
