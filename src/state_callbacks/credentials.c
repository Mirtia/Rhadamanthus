#include "state_callbacks/credentials.h"
#include <log.h>

uint32_t state_credentials_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_CREDENTIALS callback.");
    return VMI_SUCCESS;
}
