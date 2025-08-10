#ifndef SYSCALL_TABLE_H
#define SYSCALL_TABLE_H

#include <libvmi/libvmi.h>
#include <stdint.h>

#define SYSCALL_NAME_MAX_LEN 64

/* * Callback function to handle system call table updates.
 * This function will be called whenever a system call is made.
 *
 * @param vmi: The VMI instance.
 * @param context: User-defined context, can be NULL.
 * @return VMI_SUCCESS on successful inspection else VMI_FAILURE.
 */
uint32_t state_syscall_table_callback(vmi_instance_t vmi, void* context);

#endif  // SYSCALL_TABLE_H
