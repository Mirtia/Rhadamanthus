#ifndef IDT_TABLE_H
#define IDT_TABLE_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_idt_table_callback(vmi_instance_t vmi, void* context);

#endif // IDT_TABLE_H
