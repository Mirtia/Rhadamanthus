#include "state_callbacks/dir_string_matching.h"
#include <log.h>

uint32_t state_dir_string_matching_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_DIR_STRING_MATCHING callback.");
    return VMI_SUCCESS;
}
