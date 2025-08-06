#ifndef FIRMWARE_ACPI_HOOKS_H
#define FIRMWARE_ACPI_HOOKS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_firmware_acpi_hooks_callback(vmi_instance_t vmi, void* context);

#endif  // FIRMWARE_ACPI_HOOKS_H
