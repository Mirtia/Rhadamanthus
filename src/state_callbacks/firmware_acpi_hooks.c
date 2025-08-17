#include "state_callbacks/firmware_acpi_hooks.h"
#include <log.h>

uint32_t state_firmware_acpi_hooks_callback(vmi_instance_t vmi, void* context) {
    (void)vmi;
    (void)context;
    log_info("Executing STATE_FIRMWARE_ACPI_HOOKS callback.");
    return VMI_SUCCESS;
}
