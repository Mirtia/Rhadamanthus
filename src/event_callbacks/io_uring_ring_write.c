#include "event_callbacks/io_uring_ring_write.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>

/**
 * @brief Context structure for io_uring enter syscall breakpoint handling.
 */
typedef struct io_uring_bp_ctx {
  addr_t kaddr;         ///< kernel VA of __x64_sys_io_uring_enter */
  uint8_t orig;         ///< original first byte (before 0xCC) */
  vmi_event_t ss_evt;   ///< one-shot SINGLESTEP event, registered from BP cb */
  const char* symname;  ///< for logs */
} io_uring_bp_ctx_t;

/**
 * @brief Placeholder event free function that does nothing.
 */
static void vmi_event_free_noop() {}

/**
 * @brief Wrapper for vmi_read_8_va to read a single byte from a virtual address.
 */
static inline status_t read8(vmi_instance_t vmi, addr_t virtual_addr,
                             uint8_t* out) {
  return vmi_read_8_va(vmi, virtual_addr, 0, out);
}

/**
 * @brief Wrapper for vmi_write_8_va to write a single byte to a virtual address.
 */
static inline status_t write8(vmi_instance_t vmi, addr_t virtual_addr,
                              uint8_t val) {
  return vmi_write_8_va(vmi, virtual_addr, 0, &val);
}

event_response_t event_io_uring_ring_write_ss_callback(vmi_instance_t vmi,
                                                       vmi_event_t* event) {
  // The single-step handler re-arms INT3 at the entry and clears TF.
  // This keeps the entry breakpoint working for the NEXT call.
  io_uring_bp_ctx_t* ctx = (io_uring_bp_ctx_t*)event->data;

  // Re-arm INT3 at function entry
  (void)write8(vmi, ctx->kaddr, 0xCC);

  // Clear TF (trap flag, bit 8 of RFLAGS) so we don’t single-step forever.
  reg_t rflags = 0;
  (void)vmi_get_vcpureg(vmi, &rflags, RFLAGS, event->vcpu_id);
  rflags &= ~(1ULL << 8);
  (void)vmi_set_vcpureg(vmi, rflags, RFLAGS, event->vcpu_id);

  // This SINGLESTEP event is one-shot.
  // Context is passed in event.

  // TODO: Free the context.
  vmi_clear_event(vmi, event, vmi_event_free_noop);
  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t event_io_uring_ring_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  /* Entry breakpoint handler:
  *   1) Restore original byte (so the real first instruction can run),
  *   2) Enable single-step (TF=1) and rewind RIP by 1 (INT3 advanced it),
  *   3) Register a one-shot SINGLESTEP event to re-arm INT3 and clear TF,
  *   4) (Optional) Log the syscall arguments for visibility/classification.
  */
  io_uring_bp_ctx_t* ctx = (io_uring_bp_ctx_t*)event->data;

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

  // Restore original byte so the real first instruction can execute.
  (void)write8(vmi, ctx->kaddr, ctx->orig);

  // Enable TF and rewind RIP by 1 (INT3 advanced RIP by 1 byte on x86).
  reg_t rip = 0, rflags = 0;
  (void)vmi_get_vcpureg(vmi, &rip, RIP, event->vcpu_id);
  (void)vmi_get_vcpureg(vmi, &rflags, RFLAGS, event->vcpu_id);
  if (rip)
    (void)vmi_set_vcpureg(vmi, rip - 1, RIP, event->vcpu_id);
  (void)vmi_set_vcpureg(vmi, rflags | (1ULL << 8), RFLAGS,
                        event->vcpu_id); // TF=1

  // Register (or re-register) the SINGLESTEP event to re-arm INT3 afterwards.
  if (ctx->ss_evt.callback == NULL) {
    memset(&ctx->ss_evt, 0, sizeof(ctx->ss_evt));
    ctx->ss_evt.version = VMI_EVENTS_VERSION;
    ctx->ss_evt.type = VMI_EVENT_SINGLESTEP;
    ctx->ss_evt.callback = event_io_uring_ring_write_ss_callback;
    ctx->ss_evt.data = ctx; // carry context
  }
  if (vmi_register_event(vmi, &ctx->ss_evt) != VMI_SUCCESS) {
    log_warn(
        "io_uring_enter: failed to register SINGLESTEP; INT3 may not be "
        "re-armed.");
  }

  // Tell LibVMI we’re switching this vCPU into single-step. Some builds use an
  // explicit response value; if not defined, returning NONE is fine because we
  // already set TF above.
#ifdef VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
  return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
#else
  return VMI_EVENT_RESPONSE_NONE;
#endif
}
