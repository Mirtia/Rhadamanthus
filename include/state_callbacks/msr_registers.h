#ifndef MSR_REGISTERS_H
#define MSR_REGISTERS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

// See: https://vvdveen.com/data/lstar.txt
// See: MSRLSTAR: https://github.com/RouNNdeL/anti-rootkit-lkm?tab=readme-ov-file#msr-lstar
uint32_t state_msr_registers_callback(vmi_instance_t vmi, void* context);

#endif // MSR_REGISTERS_H
