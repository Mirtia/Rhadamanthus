#include "state_callbacks/process_list.h"
#include <log.h>

uint32_t state_process_list_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_PROCESS_LIST callback.");
    return VMI_SUCCESS;
}
