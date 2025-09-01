/**
 * @file ftrace_hook.h
 * @author Myrsini Gkolemi
 * @brief This file monitors ftrace hook events.
 * @version 0.0
 * @date 2025-08-24
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef FTRACE_HOOK_H
#define FTRACE_HOOK_H

#include <libvmi/events.h>

/**
 * @brief Callback function for handling ftrace hook events.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_ftrace_hook_callback(vmi_instance_t vmi,
                                            vmi_event_t* event);

#endif  // FTRACE_HOOK_H
