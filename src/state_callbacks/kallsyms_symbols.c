#include "state_callbacks/kallsyms_symbols.h"
#include <log.h>

uint32_t state_kallsyms_symbols_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_KALLSYMS_SYMBOLS callback.");
    return VMI_SUCCESS;
}
