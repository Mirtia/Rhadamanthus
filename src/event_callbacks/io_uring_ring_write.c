#include "event_callbacks/io_uring_ring_write.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include "offsets.h"
#include "utils.h"

static event_response_t event_io_uring_ring_write_ss_callback(
    vmi_instance_t vmi, vmi_event_t* event) {

  io_uring_bp_ctx_t* ctx = (io_uring_bp_ctx_t*)event->data;
  if (!ctx) {
    log_error("EVENT_IO_URING_RING_WRITE: NULL context in SS handler.");
    return VMI_EVENT_INVALID;
  }

  // Re-arm the breakpoint by writing INT3 back
  uint8_t int3 = 0xCC;
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &int3) != VMI_SUCCESS) {
    log_warn("Failed to re-arm breakpoint.");
  }

  // Disable single-step on this VCPU
  if (vmi_toggle_single_step_vcpu(vmi, event, event->vcpu_id, false) !=
      VMI_SUCCESS) {
    log_warn("Failed to disable single-step.");
  }

  log_debug("EVENT_IO_URING_RING_WRITE: Breakpoint re-armed on vCPU %u.",
            event->vcpu_id);

  log_vcpu_state(vmi, event->vcpu_id, ctx->kaddr, "SS exit");
  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t event_io_uring_ring_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    log_error("EVENT_IO_URING_RING_WRITE: Invalid arguments to callback.");
    return VMI_EVENT_INVALID;
  }

  io_uring_bp_ctx_t* ctx = (io_uring_bp_ctx_t*)event->data;
  if (!ctx) {
    log_error("EVENT_IO_URING_RING_WRITE: NULL context in INT3 handler.");
    return VMI_EVENT_INVALID;
  }

  if (ctx->kaddr == 0) {
    log_error("EVENT_IO_URING_RING_WRITE: Invalid kaddr in context.");
    return VMI_EVENT_INVALID;
  }

  event->interrupt_event.reinject = 0;
  event->interrupt_event.insn_length = 0;

  addr_t regs_addr = 0;
  if (vmi_get_vcpureg(vmi, &regs_addr, RDI, event->vcpu_id) != VMI_SUCCESS) {
    log_error("EVENT_IO_URING_RING_WRITE: Failed to get RDI for vCPU %u.",
              event->vcpu_id);
    return VMI_EVENT_INVALID;
  }

  if (regs_addr == 0) {
    log_error(
        "EVENT_IO_URING_RING_WRITE: Invalid pt_regs address (RDI=0) for vCPU "
        "%u.",
        event->vcpu_id);
    return VMI_EVENT_INVALID;
  }

  // Read fields (guest kernel VA space → dtb=0 for kernel)
  uint64_t di = 0, si = 0, dx = 0, r10 = 0, r8 = 0, r9 = 0, orig_ax = 0, ip = 0;
  vmi_read_64_va(vmi, regs_addr + LINUX_PTREGS_OFF_DI, 0, &di);
  vmi_read_64_va(vmi, regs_addr + LINUX_PTREGS_OFF_SI, 0, &si);
  vmi_read_64_va(vmi, regs_addr + LINUX_PTREGS_OFF_DX, 0, &dx);
  vmi_read_64_va(vmi, regs_addr + LINUX_PTREGS_OFF_R10, 0, &r10);
  vmi_read_64_va(vmi, regs_addr + LINUX_PTREGS_OFF_R8, 0, &r8);
  vmi_read_64_va(vmi, regs_addr + LINUX_PTREGS_OFF_R9, 0, &r9);
  vmi_read_64_va(vmi, regs_addr + LINUX_PTREGS_OFF_ORIG_AX, 0, &orig_ax);
  vmi_read_64_va(vmi, regs_addr + LINUX_PTREGS_OFF_IP, 0, &ip);

  unsigned int file_descriptor = (unsigned int)di;
  unsigned int to_submit = (unsigned int)si;
  unsigned int min_cq = (unsigned int)dx;
  unsigned int flags = (unsigned int)r10;
  uint64_t sig_ptr = r8;
  size_t sigsz = (size_t)r9;
  unsigned long user_ip = ip;
  unsigned long scno = (unsigned long)orig_ax;

  log_warn(
      "EVENT_IO_URING_RING_WRITE: __x64_sys_io_uring_enter: scno=%lu fd=%u "
      "submit=%u min_cq=%u flags=0x%x "
      "sig=%#" PRIx64 " sigsz=%zu RIP=%#" PRIx64,
      scno, file_descriptor, to_submit, min_cq, flags, sig_ptr, sigsz, user_ip);

  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &ctx->orig) != VMI_SUCCESS) {
    log_error(
        "EVENT_IO_URING_RING_WRITE: Failed to restore original byte at "
        "0x%" PRIx64,
        (uint64_t)ctx->kaddr);
    return VMI_EVENT_INVALID;
  }

  memset(&ctx->ss_evt, 0, sizeof(ctx->ss_evt));
  ctx->ss_evt.version = VMI_EVENTS_VERSION;
  ctx->ss_evt.type = VMI_EVENT_SINGLESTEP;
  ctx->ss_evt.callback = event_io_uring_ring_write_ss_callback;
  ctx->ss_evt.data = ctx;
  ctx->ss_evt.ss_event.enable = 1;

  if (vmi_register_event(vmi, &ctx->ss_evt) != VMI_SUCCESS) {
    log_warn(
        "EVENT_IO_URING_RING_WRITE: Failed to register SINGLESTEP event. "
        "Breakpoint will not be re-armed");
    return VMI_EVENT_RESPONSE_NONE;
  }

  if (vmi_toggle_single_step_vcpu(vmi, &ctx->ss_evt, event->vcpu_id, true) !=
      VMI_SUCCESS) {
    log_warn(
        "EVENT_IO_URING_RING_WRITE: Failed to enable single-step on vCPU %u. "
        "Breakpoint will not be re-armed",
        event->vcpu_id);
  }

  log_debug("EVENT_IO_URING_RING_WRITE: Single-step enabled on vCPU %u.",
            event->vcpu_id);

  log_vcpu_state(vmi, event->vcpu_id, ctx->kaddr, "CB exit");

  return VMI_EVENT_RESPONSE_NONE;
}
