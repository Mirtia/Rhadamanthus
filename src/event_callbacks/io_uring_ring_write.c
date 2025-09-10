#include "event_callbacks/io_uring_ring_write.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/responses/io_uring_ring_write_response.h"
#include "json_serializer.h"
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
    return log_error_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE, INVALID_ARGUMENTS,
        "Invalid arguments to io_uring ring write callback.");
  }

  io_uring_bp_ctx_t* ctx = (io_uring_bp_ctx_t*)event->data;
  if (!ctx) {
    return log_error_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE, INVALID_ARGUMENTS,
        "NULL context in INT3 handler.");
  }

  if (ctx->kaddr == 0) {
    return log_error_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE, INVALID_ARGUMENTS,
        "Invalid kaddr in context.");
  }

  uint32_t vcpu_id = event->vcpu_id;
  uint64_t rip = 0, cr3 = 0, rsp = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
  }

  event->interrupt_event.reinject = 0;
  event->interrupt_event.insn_length = 0;

  addr_t regs_addr = 0;
  if (vmi_get_vcpureg(vmi, &regs_addr, RDI, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE, VMI_OP_FAILURE,
        "Failed to get RDI register value.");
  }

  if (regs_addr == 0) {
    return log_error_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE, INVALID_ARGUMENTS,
        "Invalid pt_regs address (RDI=0).");
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

  io_uring_ring_write_data_t* io_uring_data = io_uring_ring_write_data_new(
      vcpu_id, rip, rsp, cr3, ctx->kaddr, regs_addr, file_descriptor, to_submit,
      min_cq, flags, sig_ptr, sigsz, user_ip, scno);
  if (!io_uring_data) {
    return log_error_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE,
        MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for io_uring ring write data.");
  }

  log_warn(
      "EVENT_IO_URING_RING_WRITE: __x64_sys_io_uring_enter: scno=%lu fd=%u "
      "submit=%u min_cq=%u flags=0x%x "
      "sig=%#" PRIx64 " sigsz=%zu RIP=%#" PRIx64,
      scno, file_descriptor, to_submit, min_cq, flags, sig_ptr, sigsz, user_ip);

  // io_uring operations can be security-relevant due to their asynchronous nature and potential for abuse
  log_warn(
      "io_uring system call intercepted - potential for advanced I/O "
      "manipulation or exploitation");

  // Restore original byte
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &ctx->orig) != VMI_SUCCESS) {
    io_uring_ring_write_data_free(io_uring_data);
    return log_error_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE, VMI_OP_FAILURE,
        "Failed to restore original byte.");
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
    // Still return success for the response since we captured the event
    return log_success_and_queue_response_interrupt(
        "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE,
        (void*)io_uring_data, (void (*)(void*))io_uring_ring_write_data_free);
  }

  if (vmi_toggle_single_step_vcpu(vmi, &ctx->ss_evt, vcpu_id, true) !=
      VMI_SUCCESS) {
    log_warn(
        "EVENT_IO_URING_RING_WRITE: Failed to enable single-step on vCPU %u. "
        "Breakpoint will not be re-armed",
        vcpu_id);
  }

  log_debug("EVENT_IO_URING_RING_WRITE: Single-step enabled on vCPU %u.",
            vcpu_id);

  log_vcpu_state(vmi, vcpu_id, ctx->kaddr, "CB exit");

  return log_success_and_queue_response_interrupt(
      "io_uring_ring_write", INTERRUPT_IO_URING_RING_WRITE,
      (void*)io_uring_data, (void (*)(void*))io_uring_ring_write_data_free);
}