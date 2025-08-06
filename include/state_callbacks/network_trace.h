#ifndef NETWORK_TRACE_H
#define NETWORK_TRACE_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_network_trace_callback(vmi_instance_t vmi, void* context);

#endif // NETWORK_TRACE_H
