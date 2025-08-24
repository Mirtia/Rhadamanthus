#include "state_callbacks/ebpf_artifacts.h"
#include <log.h>

uint32_t state_ebpf_artifacts_callback(vmi_instance_t vmi, void* context) {
    (void)context;
    log_info("Executing STATE_EBPF_ARTIFACTS callback.");
    return VMI_SUCCESS;
}
