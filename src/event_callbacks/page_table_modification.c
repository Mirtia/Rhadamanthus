#include "event_callbacks/page_table_modification.h"
#include <log.h>

event_response_t event_page_table_modification_callback(vmi_instance_t vmi,
                                                        vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    log_error(
        "PAGE_TABLE_MODIFICATION: Invalid arguments to page table modification callback.");
    return VMI_EVENT_RESPONSE_NONE;
  }

  pt_watch_ctx_t* ctx = (pt_watch_ctx_t*)event->data;
  if (!ctx) {
    log_warn("PAGE_TABLE_MODIFICATION: Missing context (event->data == NULL)");
    return VMI_EVENT_RESPONSE_NONE;
  }

  // Read current PML4 page (4096 bytes = 512 entries × 8 bytes each).
  uint64_t pml4_snapshot[512] = {0};
  if (vmi_read_pa(vmi, ctx->pml4_pa, sizeof(pml4_snapshot), pml4_snapshot,
                  NULL) != VMI_SUCCESS) {
    log_warn("PAGE_TABLE_MODIFICATION: vmi_read_pa failed @0x%lx",
             (unsigned long)ctx->pml4_pa);
    return VMI_EVENT_RESPONSE_NONE;
  }

  // First invocation initializes the shadow copy.
  if (!ctx->shadow_valid) {
    memcpy(ctx->shadow, pml4_snapshot, sizeof(pml4_snapshot));
    ctx->shadow_valid = 1;
    log_info("PAGE_TABLE_MODIFICATION: Initialized PML4 shadow @0x%lx",
             (unsigned long)ctx->pml4_pa);
    return VMI_EVENT_RESPONSE_NONE;
  }

  // Compare each entry in the PML4.
  for (unsigned index = 0; index < 512; index++) {
    uint64_t old_entry = ctx->shadow[index];
    uint64_t new_entry = pml4_snapshot[index];
    if (old_entry == new_entry)
      continue;

    // Decode key bits of the entry for analysis
    unsigned long old_present = (old_entry & 0x1) != 0;
    unsigned long new_present = (new_entry & 0x1) != 0;

    unsigned long old_writable = (old_entry >> 1) & 1;
    unsigned long new_writable = (new_entry >> 1) & 1;

    unsigned long old_user = (old_entry >> 2) & 1;
    unsigned long new_user = (new_entry >> 2) & 1;

    unsigned long old_noexec = (old_entry >> 63) & 1;
    unsigned long new_noexec = (new_entry >> 63) & 1;

    log_info(
        "PAGE_TABLE_MODIFICATION: PML4 entry [%3u] updated "
        "(old=0x%016llx, new=0x%016llx): "
        "Present %d→%d, Writable %d→%d, User-access %d→%d, NX %d→%d",
        index, old_entry, new_entry, old_present, new_present, old_writable,
        new_writable, old_user, new_user, old_noexec, new_noexec);

    // Update shadow with latest version.
    ctx->shadow[index] = new_entry;
  }

  return VMI_EVENT_RESPONSE_NONE;
}
