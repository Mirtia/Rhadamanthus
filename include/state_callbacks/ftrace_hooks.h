#ifndef FTRACE_HOOKS_H
#define FTRACE_HOOKS_H
#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_ftrace_hooks_callback(vmi_instance_t vmi, void* context);

#endif  // FTRACE_HOOKS_H