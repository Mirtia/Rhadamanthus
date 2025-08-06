#ifndef MSR_REGISTERS_H
#define MSR_REGISTERS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_msr_registers_callback(vmi_instance_t vmi, void* context);

#endif // MSR_REGISTERS_H
