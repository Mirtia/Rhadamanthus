#include "state_callbacks/kernel_code_integrity_check.h"
#include <log.h>

uint32_t state_kernel_code_integrity_check_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_KERNEL_CODE_INTEGRITY_CHECK callback.");
    return VMI_SUCCESS;
}
