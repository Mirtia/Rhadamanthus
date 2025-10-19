#include "event_callbacks/page_table_modification.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/responses/page_table_modification_response.h"
#include "json_serializer.h"
#include "utils.h"

#define PAGE_MASK (~(4096 - 1ULL))

event_response_t event_page_table_modification_callback(vmi_instance_t vmi,
                                                        vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_event(
        "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION,
        INVALID_ARGUMENTS,
        "Invalid arguments to page table modification callback.");
  }

  // Get CR3 register value from the event
  uint64_t new_cr3_value = event->reg_event.value;
  uint64_t old_cr3_value = event->reg_event.previous;
  uint32_t vcpu_id = event->vcpu_id;

  // Extract PML4 base physical address: CR3[63:12]
  uint64_t new_pml4_pa = new_cr3_value & PAGE_MASK;
  uint64_t old_pml4_pa = old_cr3_value & PAGE_MASK;

  uint64_t rip = 0, cr3 = 0, rsp = 0;
  if (get_standard_registers(vmi, vcpu_id, &rip, &cr3, &rsp) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION,
        VMI_OP_FAILURE, "Failed to get standard registers.");
  }

  // Create response data structure
  page_table_modification_data_t* pt_data = page_table_modification_data_new(
      vcpu_id, rip, rsp, new_cr3_value, new_pml4_pa);
  if (!pt_data) {
    return log_error_and_queue_response_event(
        "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION,
        MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for page table modification data.");
  }

  // Read both old and new PML4 pages (4096 bytes = 512 entries × 8 bytes each)
  uint64_t old_pml4_snapshot[512] = {0};
  uint64_t new_pml4_snapshot[512] = {0};

  bool old_read_success =
      (vmi_read_pa(vmi, old_pml4_pa, sizeof(old_pml4_snapshot),
                   old_pml4_snapshot, NULL) == VMI_SUCCESS);
  bool new_read_success =
      (vmi_read_pa(vmi, new_pml4_pa, sizeof(new_pml4_snapshot),
                   new_pml4_snapshot, NULL) == VMI_SUCCESS);

  if (!new_read_success) {
    log_warn("CR3 MODIFICATION: Failed to read new PML4 page @0x%lx",
             (unsigned long)new_pml4_pa);
    page_table_modification_data_free(pt_data);
    return VMI_EVENT_RESPONSE_NONE;
  }

  log_info(
      "CR3 MODIFICATION: CR3 changed from 0x%016lx to 0x%016lx (PML4: 0x%lx -> "
      "0x%lx)",
      old_cr3_value, new_cr3_value, old_pml4_pa, new_pml4_pa);

  // If PML4 base address changed (context switch to different process)
  if (old_pml4_pa != new_pml4_pa) {
    log_warn(
        "CR3 MODIFICATION: Process context switch detected (PML4 base "
        "changed)");
  }

  // Compare PML4 entries if we can read both pages
  bool modifications_found = false;
  if (old_read_success && old_pml4_pa != new_pml4_pa) {
    for (unsigned index = 0; index < 512; index++) {
      uint64_t old_entry = old_pml4_snapshot[index];
      uint64_t new_entry = new_pml4_snapshot[index];
      if (old_entry == new_entry)
        continue;

      modifications_found = true;

      // Decode key bits of the entry for analysis
      bool old_present = (old_entry & 0x1) != 0;
      bool new_present = (new_entry & 0x1) != 0;

      bool old_writable = (old_entry >> 1) & 1;
      bool new_writable = (new_entry >> 1) & 1;

      bool old_user = (old_entry >> 2) & 1;
      bool new_user = (new_entry >> 2) & 1;

      bool old_noexec = (old_entry >> 63) & 1;
      bool new_noexec = (new_entry >> 63) & 1;

      // Add modification to response data
      page_table_modification_add_entry(pt_data, index, old_entry, new_entry,
                                        old_present, new_present, old_writable,
                                        new_writable, old_user, new_user,
                                        old_noexec, new_noexec);

      log_debug(
          "CR3 MODIFICATION: PML4 entry [%3u] differs "
          "(old=0x%016lx, new=0x%016lx): "
          "Present %d→%d, Writable %d→%d, User-access %d→%d, NX %d→%d",
          index, old_entry, new_entry, old_present, new_present, old_writable,
          new_writable, old_user, new_user, old_noexec, new_noexec);
    }
  }

  return log_success_and_queue_response_event(
      "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION, (void*)pt_data,
      (void (*)(void*))page_table_modification_data_free);
}