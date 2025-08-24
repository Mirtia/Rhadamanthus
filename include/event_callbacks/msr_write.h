/**
 * @file msr_write.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-08-24
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#ifndef MSR_WRITE_H
#define MSR_WRITE_H

#include <libvmi/events.h>

/**
 * @brief Callback function for handling MSR write events.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_msr_write_callback(vmi_instance_t vmi,
                                           vmi_event_t* event);

#endif  // MSR_WRITE_H