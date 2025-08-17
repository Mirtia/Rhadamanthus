/**
 * @file process_list.h
 * @author Myrsini Gkolemi
 * @brief Inspect the process list.
 * @version 0.0
 * @date 2025-08-10
 * 
 * @copyright Copyright (c) 2025
 * @remark The implementation is almost identical to the example process-list provided by LibVMI 
 * (https://github.com/libvmi/libvmi/blob/master/examples/process-list.c)
 */
#ifndef PROCESS_LIST_H
#define PROCESS_LIST_H

#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief Callback function to show available processes.
 *
 * @param vmi: The VMI instance.
 * @param context: User-defined context, can be NULL.
 * @return VMI_SUCCESS on successful inspection else VMI_FAILURE.
 */
uint32_t state_process_list_callback(vmi_instance_t vmi, void* context);

#endif  // PROCESS_LIST_H
