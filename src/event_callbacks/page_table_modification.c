#include "event_callbacks/page_table_modification.h"
#include <log.h>

event_response_t event_page_table_modification_callback(vmi_instance_t vmi,
                                                        vmi_event_t* event) {
  pt_watch_ctx_t* ctx = (pt_watch_ctx_t*)event->data;
  if (!ctx) {
    log_warn("PT watch: missing context (event->data == NULL)");
    return VMI_EVENT_RESPONSE_NONE;
  }

  /* Read current PML4 page (4096 bytes) by physical address. */
  uint64_t cur[512] = {0};
  if (vmi_read_pa(vmi, ctx->pml4_pa, sizeof(cur), cur, NULL) != VMI_SUCCESS) {
    log_warn("PT watch: vmi_read_pa failed @0x%lx",
             (unsigned long)ctx->pml4_pa);
    return VMI_EVENT_RESPONSE_NONE;
  }

  /* First hit primes the shadow, no diff output. */
  if (!ctx->shadow_valid) {
    memcpy(ctx->shadow, cur, sizeof(cur));
    ctx->shadow_valid = 1;
    log_info("PT watch: primed PML4 shadow @0x%lx",
             (unsigned long)ctx->pml4_pa);
    return VMI_EVENT_RESPONSE_NONE;
  }

  /* Diff entries; report changed ones. */
  for (unsigned i = 0; i < 512; i++) {
    uint64_t oldv = ctx->shadow[i];
    uint64_t newv = cur[i];
    if (oldv == newv)
      continue;

    /* Decode a few critical bits for context. */
    unsigned long old_p = (oldv & 0x1) != 0;
    unsigned long new_p = (newv & 0x1) != 0;
    unsigned long old_rw = (oldv >> 1) & 1, new_rw = (newv >> 1) & 1;
    unsigned long old_us = (oldv >> 2) & 1, new_us = (newv >> 2) & 1;
    unsigned long old_nx = (oldv >> 63) & 1, new_nx = (newv >> 63) & 1;

    log_info(
        "PML4E[%3u] changed: old=0x%016llx new=0x%016llx  "
        "P:%d→%d RW:%d→%d US:%d→%d NX:%d→%d",
        i, oldv, newv, old_p, new_p, old_rw, new_rw, old_us, new_us, old_nx,
        new_nx);

    /* Update shadow so subsequent writes diff against newest state. */
    ctx->shadow[i] = newv;
  }

  return VMI_EVENT_RESPONSE_NONE;
}