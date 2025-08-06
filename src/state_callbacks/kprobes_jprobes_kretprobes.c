#include "state_callbacks/kprobes_jprobes_kretprobes.h"
#include <log.h>

uint32_t state_kprobes_jprobes_kretprobes_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_KPROBES_JPROBES_KRETPROBES callback.");
    return VMI_SUCCESS;
}
