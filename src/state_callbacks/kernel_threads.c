#include "state_callbacks/kernel_threads.h"
#include <log.h>

uint32_t state_kernel_threads_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_KERNEL_THREADS callback.");
    return VMI_SUCCESS;
}
