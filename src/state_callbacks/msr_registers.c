#include "state_callbacks/msr_registers.h"
#include <log.h>

uint32_t state_msr_registers_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_MSR_REGISTERS callback.");
    return VMI_SUCCESS;
}
