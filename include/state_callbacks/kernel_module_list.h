#ifndef KERNEL_MODULE_LIST_H
#define KERNEL_MODULE_LIST_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_kernel_module_list_callback(vmi_instance_t vmi, void* context);

#endif // KERNEL_MODULE_LIST_H
