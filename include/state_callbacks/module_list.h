#ifndef MODULE_LIST_H
#define MODULE_LIST_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_module_list_callback(vmi_instance_t vmi, void* context);

#endif // MODULE_LIST_H
