#include "state_callbacks/io_uring_artifacts.h"
#include <log.h>

uint32_t state_io_uring_artifacts_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_IO_URING_ARTIFACTS callback.");
    return VMI_SUCCESS;
}
