/**
 * @file page_table_modification.h
 * @brief This file monitors the page table modifications by tracking changes in the PML4 entries.
 * @version 0.0
 * @date 2025-08-24
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef PAGE_TABLE_MODIFICATION_H
#define PAGE_TABLE_MODIFICATION_H

#include <libvmi/events.h>

/**
 * @brief Tracks the PML4 page (CR3 & ~0xFFF) and a shadow copy of its 512 entries 
 */
struct pt_watch_ctx_t {
  addr_t
      pml4_pa;  ///< Physical address of PML4 page (CR3 base) (PML4 -> PDPT -> PD -> PT).
  uint64_t shadow
      [512];  ///< Last-seen PML4 entries (detect modifications over time, comparison with snapshot).
  uint8_t shadow_valid;  ///< 0 until we successfully snapshot once.
};

typedef struct pt_watch_ctx_t pt_watch_ctx_t;

/**
 * @brief Callback function for handling page table modification events.
 *
 * @details It is applicable for rootkits targeting hypervisors in x86_64 (e.g. BluePill).
 *
 * @param vmi The VMI instance.
 * @param event The event that triggered the callback.
 * @return event_response_t VMI_EVENT_RESPONSE_NONE (general monitoring).
 */
event_response_t event_page_table_modification_callback(vmi_instance_t vmi,
                                                        vmi_event_t* event);

#endif  // PAGE_TABLE_MODIFICATION_H
