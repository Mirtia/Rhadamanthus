#include "state_callbacks/syscall_table.h"
#include <log.h>

uint32_t state_syscall_table_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_SYSCALL_TABLE callback.");
    return VMI_SUCCESS;
}
