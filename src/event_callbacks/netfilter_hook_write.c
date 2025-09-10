#include "event_callbacks/netfilter_hook_write.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "event_callbacks/responses/netfilter_hook_write_response.h"
#include "event_handler.h"
#include "json_serializer.h"
#include "offsets.h"
#include "utils.h"

static event_response_t event_netfilter_hook_write_ss_callback(
    vmi_instance_t vmi, vmi_event_t* event) {

  nf_bp_ctx_t* ctx = (nf_bp_ctx_t*)event->data;
  if (!ctx) {
    log_error("INTERRUPT_NETFILTER_HOOK_WRITE: NULL context in SS handler.");
    return VMI_EVENT_INVALID;
  }

  // Re-arm the breakpoint by writing INT3 back
  uint8_t int3 = 0xCC;
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &int3) != VMI_SUCCESS) {
    log_warn("Failed to re-arm breakpoint");
  }

  // Disable single-step on this VCPU
  if (vmi_toggle_single_step_vcpu(vmi, event, event->vcpu_id, false) !=
      VMI_SUCCESS) {
    log_warn("Failed to disable single-step");
  }

  log_debug("INTERRUPT_NETFILTER_HOOK_WRITE: Breakpoint re-armed on vCPU %u",
            event->vcpu_id);

  log_vcpu_state(vmi, event->vcpu_id, ctx->kaddr, "SS exit");
  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t event_netfilter_hook_write_callback(vmi_instance_t vmi,
                                                     vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE,
        INVALID_ARGUMENTS,
        "Invalid arguments to netfilter hook write callback.");
  }

  nf_bp_ctx_t* ctx = (nf_bp_ctx_t*)event->data;
  if (!ctx) {
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE,
        INVALID_ARGUMENTS, "NULL context in INT3 handler.");
  }

  if (ctx->kaddr == 0) {
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE,
        INVALID_ARGUMENTS, "Invalid kaddr in context.");
  }

  uint32_t vcpu_id = event->vcpu_id;
  uint64_t rip = 0, cr3 = 0, rsp = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
  }

  event->interrupt_event.reinject = 0;
  event->interrupt_event.insn_length = 0;

  // Expected calling convention (x86_64 SysV):
  // * RDI = struct net *net
  // * RSI = const struct nf_hook_ops *ops
  // * RDX = size_t n   (only for nf_register_net_hooks)
  reg_t rdi = 0, rsi = 0, rdx = 0;
  if (vmi_get_vcpureg(vmi, &rdi, RDI, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE, VMI_OP_FAILURE,
        "Failed to get RDI register value.");
  }
  if (vmi_get_vcpureg(vmi, &rsi, RSI, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE, VMI_OP_FAILURE,
        "Failed to get RSI register value.");
  }
  if (vmi_get_vcpureg(vmi, &rdx, RDX, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE, VMI_OP_FAILURE,
        "Failed to get RDX register value.");
  }

  netfilter_hook_write_data_t* nf_data = netfilter_hook_write_data_new(
      vcpu_id, rip, rsp, cr3, ctx->kaddr, (uint64_t)rdi, (uint64_t)rsi,
      (uint64_t)rdx, ctx->symname);
  if (!nf_data) {
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE,
        MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for netfilter hook write data.");
  }

  log_debug("INTERRUPT_NETFILTER_HOOK_WRITE: %s @0x%" PRIx64 " net=0x%" PRIx64
            " ops=0x%" PRIx64 " n=%llu",
            ctx->symname ? ctx->symname : "nf_register_net_hook", ctx->kaddr,
            (uint64_t)rdi, (uint64_t)rsi, (unsigned long long)rdx);

  // Netfilter hook registration can be used by rootkits to intercept network traffic
  log_warn(
      "Netfilter hook registration detected - potential network interception "
      "capability");

  // Restore original byte
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &ctx->orig) != VMI_SUCCESS) {
    netfilter_hook_write_data_free(nf_data);
    return log_error_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE, VMI_OP_FAILURE,
        "Failed to restore original byte.");
  }

  memset(&ctx->ss_evt, 0, sizeof(ctx->ss_evt));
  ctx->ss_evt.version = VMI_EVENTS_VERSION;
  ctx->ss_evt.type = VMI_EVENT_SINGLESTEP;
  ctx->ss_evt.callback = event_netfilter_hook_write_ss_callback;
  ctx->ss_evt.data = ctx;
  ctx->ss_evt.ss_event.enable = 1;

  if (vmi_register_event(vmi, &ctx->ss_evt) != VMI_SUCCESS) {
    log_warn(
        "INTERRUPT_NETFILTER_HOOK_WRITE: Failed to register SINGLESTEP event. "
        "Breakpoint will not be re-armed");
    // Still return success for the response since we captured the event
    return log_success_and_queue_response_interrupt(
        "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE, (void*)nf_data,
        (void (*)(void*))netfilter_hook_write_data_free);
  }

  if (vmi_toggle_single_step_vcpu(vmi, &ctx->ss_evt, vcpu_id, true) !=
      VMI_SUCCESS) {
    log_warn(
        "INTERRUPT_NETFILTER_HOOK_WRITE: Failed to enable single-step on vCPU "
        "%u. "
        "Breakpoint will not be re-armed",
        vcpu_id);
  }

  log_debug("INTERRUPT_NETFILTER_HOOK_WRITE: Single-step enabled on vCPU %u",
            vcpu_id);

  log_vcpu_state(vmi, vcpu_id, ctx->kaddr, "CB exit");

  return log_success_and_queue_response_interrupt(
      "netfilter_hook_write", INTERRUPT_NETFILTER_HOOK_WRITE, (void*)nf_data,
      (void (*)(void*))netfilter_hook_write_data_free);
}