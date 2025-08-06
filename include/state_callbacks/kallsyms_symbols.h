#ifndef KALLSYMS_SYMBOLS_H
#define KALLSYMS_SYMBOLS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_kallsyms_symbols_callback(vmi_instance_t vmi, void* context);

#endif // KALLSYMS_SYMBOLS_H
