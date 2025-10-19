/**
 * @file page_table_modification.h
 * @brief This file monitors the page table modifications by tracking CR3 register changes.
 * @version 0.1
 * @date 2025-10-19
 *
 * @copyright GNU Lesser General Public License v2.1
 *
 */
#ifndef PAGE_TABLE_MODIFICATION_H
#define PAGE_TABLE_MODIFICATION_H

#include <libvmi/events.h>

/**
 * @brief Callback function for handling CR3 register modification events.
 *
 * @details Monitors CR3 register writes to detect page table base address changes,
 * which can indicate process context switches or page table modifications.
 * This is applicable for detecting rootkits that manipulate page tables or
 * hypervisors in x86_64 architectures (e.g. BluePill).
 *
 * @param vmi The VMI instance.
 * @param event The CR3 register event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_page_table_modification_callback(vmi_instance_t vmi,
                                                        vmi_event_t* event);

#endif  // PAGE_TABLE_MODIFICATION_H
