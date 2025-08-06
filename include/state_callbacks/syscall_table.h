#ifndef SYSCALL_TABLE_H
#define SYSCALL_TABLE_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_syscall_table_callback(vmi_instance_t vmi, void* context);

#endif // SYSCALL_TABLE_H
