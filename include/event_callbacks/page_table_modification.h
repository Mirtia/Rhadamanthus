/**
 * @file page_table_modification.h
 * @author Myrsini Gkolemi
 * @brief 
 * @version 0.0
 * @date 2025-08-24
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef PAGE_TABLE_MODIFICATION_H
#define PAGE_TABLE_MODIFICATION_H

#include <libvmi/events.h>

/* Tracks the PML4 page (CR3 & ~0xFFF) and a shadow copy of its 512 entries. */
typedef struct {
  addr_t pml4_pa;       /* physical address of PML4 page (CR3 base) */
  uint64_t shadow[512]; /* last-seen PML4 entries */
  uint8_t shadow_valid; /* 0 until we successfully snapshot once */
} pt_watch_ctx_t;

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
