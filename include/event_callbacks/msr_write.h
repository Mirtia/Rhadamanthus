/**
 * @file msr_write.h
 * @author Myrsini Gkolemi
 * @brief The file monitors MSR register write events.
 * @version 0.0
 * @date 2025-08-24
 *
 * @copyright GNU Lesser General Public License v2.1
 *
 */
#ifndef MSR_WRITE_H
#define MSR_WRITE_H

#include <libvmi/events.h>

/**
 * @brief Callback function for handling MSR write events.
 *
 * @details This event was inspired by the LSTAR PoC https://vvdveen.com/data/lstar.txt. 
 * The main idea is that every time there is a syscall instruction, the processor stores RIP in RCX
 * and goes to the LSTAR MSR register address, which is the system call entry point. In other words, the 
 * target is to modify the system call entry point.
 *
 * @todo Fix PoC. Adjust the way to retrieve OLD_RSP and KERNEL_STACK addresses. Or just test on the older kernel :(.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_msr_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event);

#endif  // MSR_WRITE_H