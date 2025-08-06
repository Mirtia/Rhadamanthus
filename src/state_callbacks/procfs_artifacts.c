#include "state_callbacks/procfs_artifacts.h"
#include <log.h>

uint32_t state_procfs_artifacts_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_PROCFS_ARTIFACTS callback.");
    return VMI_SUCCESS;
}
