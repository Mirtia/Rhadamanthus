/**
 * @file kernel_module_list.h
 * @author Myrsini Gkolemi
 * @brief This file contains the callback function to list kernel modules.
 * @version 0.0
 * @date 2025-08-10
 * 
 * @copyright Copyright (c) 2025
 * @remark The implementation is almost identical to the example process-list provided by LibVMI 
 * (https://github.com/libvmi/libvmi/blob/master/examples/module-list.c)
 */
#ifndef KERNEL_MODULE_LIST_H
#define KERNEL_MODULE_LIST_H

#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief List kernel modules callback for VMI-based security monitoring
 * 
 * @param vmi The VMI instance.
 * @param context The user-defined context [unused].
 * @return uint32_t VMI_SUCCESS on successful inspection, else VMI_FAILURE.
 */
uint32_t state_kernel_module_list_callback(vmi_instance_t vmi, void* context);

#endif  // KERNEL_MODULE_LIST_H
