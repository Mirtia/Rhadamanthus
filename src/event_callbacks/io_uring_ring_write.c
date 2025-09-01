#include "event_callbacks/io_uring_ring_write.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>

/**
 * @brief No-op free routine with the correct signature for vmi_event_free_t.
 */
static void vmi_event_free_noop(vmi_event_t* evt, status_t rc) {
  (void)evt;
  (void)rc;
  log_debug("(҂ `з´) ︻╦̵̵̿╤──");
}

static event_response_t event_io_uring_ring_write_ss_callback(
    vmi_instance_t vmi, vmi_event_t* event) {
  // One-step handler: re-arm INT3 and turn off single-step on this vCPU.
  io_uring_bp_ctx_t* ctx = (io_uring_bp_ctx_t*)event->data;
  if (!ctx)
    return VMI_EVENT_INVALID;

  // Re-arm INT3 at function entry.
  uint8_t val = 0xCC;
  (void)vmi_write_8_va(vmi, ctx->kaddr, 0, &val);

  // Disable MTF-based single-step for this vCPU via LibVMI.
  (void)vmi_toggle_single_step_vcpu(vmi, event, event->vcpu_id, false);

  vmi_clear_event(vmi, event, vmi_event_free_noop);

  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t event_io_uring_ring_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    log_error("EVENT_IO_URING_RING_WRITE: Invalid arguments to callback.");
    return VMI_EVENT_INVALID;
  }

  /* Entry breakpoint handler (INT3/0xCC delivered via VMI_EVENT_INTERRUPT:INT3):
   *  - Restore original byte (so the real first instruction can run),
   *  - Rewind RIP by 1 (INT3 advanced it),
   *  - Ensure a SINGLESTEP event is registered,
   *  - Enable single-step via vmi_toggle_single_step_vcpu (no direct TF twiddling).
   */
  io_uring_bp_ctx_t* ctx = (io_uring_bp_ctx_t*)event->data;
  if (!ctx)
    return VMI_EVENT_INVALID;

  // Grab syscall-style args for logging:
  reg_t rdi = 0, rsi = 0, rdx = 0, r10 = 0, r8 = 0, r9 = 0;
  (void)vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
  (void)vmi_get_vcpureg(vmi, &rsi, RSI, event->vcpu_id);
  (void)vmi_get_vcpureg(vmi, &rdx, RDX, event->vcpu_id);
  (void)vmi_get_vcpureg(vmi, &r10, R10, event->vcpu_id);
  (void)vmi_get_vcpureg(vmi, &r8, R8, event->vcpu_id);
  (void)vmi_get_vcpureg(vmi, &r9, R9, event->vcpu_id);

  // io_uring_enter(fd=rdi, to_submit=rsi, min_complete=rdx, flags=r10, sig=r8, sigsz=r9)
  log_info("%s ENTER @0x%" PRIx64
           ": fd=%llu submit=%llu min_cq=%llu flags=0x%llx sig=%llu sigsz=%llu",
           ctx->symname ? ctx->symname : "io_uring_enter", (uint64_t)ctx->kaddr,
           (unsigned long long)rdi, (unsigned long long)rsi,
           (unsigned long long)rdx, (unsigned long long)r10,
           (unsigned long long)r8, (unsigned long long)r9);

  // Restore original first byte so the real first instruction can execute.
  {
    uint8_t val = ctx->orig;
    (void)vmi_write_8_va(vmi, ctx->kaddr, 0, &val);
  }

  // Rewind RIP by 1 (INT3 advanced RIP on x86 by one byte).
  reg_t rip = 0;
  (void)vmi_get_vcpureg(vmi, &rip, RIP, event->vcpu_id);
  if (rip)
    (void)vmi_set_vcpureg(vmi, rip - 1, RIP, event->vcpu_id);

  // Ensure the SINGLESTEP event exists and is registered once.
  if (ctx->ss_evt.callback == NULL) {
    memset(&ctx->ss_evt, 0, sizeof(ctx->ss_evt));
    ctx->ss_evt.version = VMI_EVENTS_VERSION;
    ctx->ss_evt.type = VMI_EVENT_SINGLESTEP;
    ctx->ss_evt.callback = event_io_uring_ring_write_ss_callback;
    ctx->ss_evt.data = ctx;

    if (vmi_register_event(vmi, &ctx->ss_evt) != VMI_SUCCESS) {
      log_warn(
          "io_uring_enter: failed to register SINGLESTEP; INT3 may not be "
          "re-armed.");
      // We cannot single-step without a registered handler; bail out.
      return VMI_EVENT_RESPONSE_NONE;
    }
  }

  // Turn on single-step for this vCPU using the LibVMI API (no direct TF writes).
  if (vmi_toggle_single_step_vcpu(vmi, &ctx->ss_evt, event->vcpu_id, true) !=
      VMI_SUCCESS) {
    log_warn(
        "io_uring_enter: failed to enable SINGLESTEP on vCPU %u; INT3 may not "
        "be re-armed.",
        event->vcpu_id);
  }

  return VMI_EVENT_RESPONSE_NONE;
}
