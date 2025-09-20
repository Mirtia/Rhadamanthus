#include "event_callbacks/page_table_modification.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/responses/page_table_modification_response.h"
#include "json_serializer.h"
#include "utils.h"

event_response_t event_page_table_modification_callback(vmi_instance_t vmi,
                                                        vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_event(
        "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION,
        INVALID_ARGUMENTS,
        "Invalid arguments to page table modification callback.");
  }

  pt_watch_ctx_t* ctx = (pt_watch_ctx_t*)event->data;
  if (!ctx) {
    return log_error_and_queue_response_event(
        "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION,
        INVALID_ARGUMENTS, "Missing context (event->data == NULL)");
  }

  uint32_t vcpu_id = event->vcpu_id;
  uint64_t rip = 0, cr3 = 0, rsp = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION,
        VMI_OP_FAILURE, "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION,
        VMI_OP_FAILURE, "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION,
        VMI_OP_FAILURE, "Failed to get RSP register value.");
  }

  // Read current PML4 page (4096 bytes = 512 entries × 8 bytes each).
  uint64_t pml4_snapshot[512] = {0};
  if (vmi_read_pa(vmi, ctx->pml4_pa, sizeof(pml4_snapshot), pml4_snapshot,
                  NULL) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION,
        VMI_OP_FAILURE, "Failed to read PML4 page.");
  }

  // First invocation initializes the shadow copy.
  if (!ctx->shadow_valid) {
    memcpy(ctx->shadow, pml4_snapshot, sizeof(pml4_snapshot));
    ctx->shadow_valid = 1;
    log_info("PAGE_TABLE_MODIFICATION: Initialized PML4 shadow @0x%lx",
             (unsigned long)ctx->pml4_pa);
    return VMI_EVENT_RESPONSE_NONE;
  }

  // Create response data structure
  page_table_modification_data_t* pt_data =
      page_table_modification_data_new(vcpu_id, rip, rsp, cr3, ctx->pml4_pa);
  if (!pt_data) {
    return log_error_and_queue_response_event(
        "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION,
        MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for page table modification data.");
  }

  // Compare each entry in the PML4.
  bool modifications_found = false;
  for (unsigned index = 0; index < 512; index++) {
    uint64_t old_entry = ctx->shadow[index];
    uint64_t new_entry = pml4_snapshot[index];
    if (old_entry == new_entry)
      continue;

    modifications_found = true;

    // Decode key bits of the entry for analysis
    unsigned long old_present = (old_entry & 0x1) != 0;
    unsigned long new_present = (new_entry & 0x1) != 0;

    unsigned long old_writable = (old_entry >> 1) & 1;
    unsigned long new_writable = (new_entry >> 1) & 1;

    unsigned long old_user = (old_entry >> 2) & 1;
    unsigned long new_user = (new_entry >> 2) & 1;

    unsigned long old_noexec = (old_entry >> 63) & 1;
    unsigned long new_noexec = (new_entry >> 63) & 1;

    // Add modification to response data
    page_table_modification_add_entry(
        pt_data, index, old_entry, new_entry, old_present, new_present,
        old_writable, new_writable, old_user, new_user, old_noexec, new_noexec);

    log_warn(
        "PAGE_TABLE_MODIFICATION: PML4 entry [%3u] updated "
        "(old=0x%016llx, new=0x%016llx): "
        "Present %d→%d, Writable %d→%d, User-access %d→%d, NX %d→%d",
        index, old_entry, new_entry, old_present, new_present, old_writable,
        new_writable, old_user, new_user, old_noexec, new_noexec);

    ctx->shadow[index] = new_entry;
  }

  if (!modifications_found) {
    // No modifications detected, clean up and return
    page_table_modification_data_free(pt_data);
    return VMI_EVENT_RESPONSE_NONE;
  }

  // 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩 😩
  vmi_clear_event(vmi, event, NULL);
  vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

  return log_success_and_queue_response_event(
      "page_table_modification", EVENT_PAGE_TABLE_MODIFICATION, (void*)pt_data,
      (void (*)(void*))page_table_modification_data_free);
}