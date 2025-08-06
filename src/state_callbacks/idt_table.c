#include "state_callbacks/idt_table.h"
#include <log.h>

uint32_t state_idt_table_callback(vmi_instance_t vmi, void* context) {
    log_info("Executing STATE_IDT_TABLE callback.");
    return VMI_SUCCESS;
}
