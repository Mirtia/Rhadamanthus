/**
 * @file page_table_modification.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-08-24
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#ifndef PAGE_TABLE_MODIFICATION_H
#define PAGE_TABLE_MODIFICATION_H

#include <libvmi/events.h>

/**
 * @brief Callback function for handling page table modification events.
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_page_table_modification_callback(vmi_instance_t vmi,
                                                        vmi_event_t* event);
                                                        
#endif  // PAGE_TABLE_MODIFICATION_H
