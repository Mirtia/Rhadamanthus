/**
 * @file syscall_table_write.h
 * @author Myrsini Gkolemi
 * @brief 
 * @version 0.0
 * @date 2025-08-24
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef SYSCALL_TABLE_WRITE_H
#define SYSCALL_TABLE_WRITE_H

#include <libvmi/events.h>

/**
 * @brief Callback function for handling syscall table write events.
 *
 * This function is triggered when the syscall table is modified in the guest VM.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_syscall_table_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event);

#endif  // SYSCALL_TABLE_WRITE_H
