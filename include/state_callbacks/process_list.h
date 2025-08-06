#ifndef PROCESS_LIST_H
#define PROCESS_LIST_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_process_list_callback(vmi_instance_t vmi, void* context);

#endif // PROCESS_LIST_H
