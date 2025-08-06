#ifndef KERNEL_THREADS_H
#define KERNEL_THREADS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_kernel_threads_callback(vmi_instance_t vmi, void* context);

#endif // KERNEL_THREADS_H
