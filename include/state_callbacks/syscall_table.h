/**
 * @file syscall_table.h
 * @author Myrsini Gkolemi
 * @brief Inspect if there are modifications in the system call table.
 * @version 0.0
 * @date 2025-08-10
 * 
 * @copyright GNU Lesser General Public License v2.1
 * @remark The implementation of this file is closely replicating the behavior of idt-check by https://github.com/tianweiz07/Cloud_Integrity 
 * (https://github.com/tianweiz07/Cloud_Integrity/blob/master/src/syscall-check.c)
 */
#ifndef SYSCALL_TABLE_H
#define SYSCALL_TABLE_H

#include <libvmi/libvmi.h>
#include <stdint.h>

#define SYSCALL_NAME_MAX_LEN 64

/**  
 * Callback function to handle system call table updates.
 * This function will be called whenever a system call is made.
 *
 * @param vmi: The VMI instance.
 * @param context: User-defined context, can be NULL.
 * @return VMI_SUCCESS on successful inspection else VMI_FAILURE.
 */
uint32_t state_syscall_table_callback(vmi_instance_t vmi, void* context);

#endif  // SYSCALL_TABLE_H
