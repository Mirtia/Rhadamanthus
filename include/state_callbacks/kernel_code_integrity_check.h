#ifndef KERNEL_CODE_INTEGRITY_CHECK_H
#define KERNEL_CODE_INTEGRITY_CHECK_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_kernel_code_integrity_check_callback(vmi_instance_t vmi, void* context);

#endif // KERNEL_CODE_INTEGRITY_CHECK_H
