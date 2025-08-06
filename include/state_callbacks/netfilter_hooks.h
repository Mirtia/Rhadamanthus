#ifndef NETFILTER_HOOKS_H
#define NETFILTER_HOOKS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_netfilter_hooks_callback(vmi_instance_t vmi, void* context);

#endif // NETFILTER_HOOKS_H
