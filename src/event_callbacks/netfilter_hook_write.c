#include "event_callbacks/netfilter_hook_write.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "event_handler.h"
#include "offsets.h"
#include "utils.h"

static event_response_t event_netfilter_hook_write_ss_callback(
    vmi_instance_t vmi, vmi_event_t* event) {

  nf_bp_ctx_t* ctx = (nf_bp_ctx_t*)event->data;
  if (!ctx) {
    log_error("EVENT_NETFILTER_HOOK_WRITE: NULL context in SS handler.");
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

  log_debug("EVENT_NETFILTER_HOOK_WRITE: Breakpoint re-armed on vCPU %u",
           event->vcpu_id);

  log_vcpu_state(vmi, event->vcpu_id, ctx->kaddr, "SS exit");
  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t event_netfilter_hook_write_callback(vmi_instance_t vmi,
                                                     vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    log_error("EVENT_NETFILTER_HOOK_WRITE: Invalid arguments to callback.");
    return VMI_EVENT_INVALID;
  }

  nf_bp_ctx_t* ctx = (nf_bp_ctx_t*)event->data;
  if (!ctx) {
    log_error("EVENT_NETFILTER_HOOK_WRITE: NULL context in INT3 handler.");
    return VMI_EVENT_INVALID;
  }

  if (ctx->kaddr == 0) {
    log_error("EVENT_NETFILTER_HOOK_WRITE: Invalid kaddr in context.");
    return VMI_EVENT_INVALID;
  }

  event->interrupt_event.reinject = 0;
  event->interrupt_event.insn_length = 0;

  // Expected calling convention (x86_64 SysV):
  // * RDI = struct net *net
  // * RSI = const struct nf_hook_ops *ops
  // * RDX = size_t n   (only for nf_register_net_hooks)
  reg_t rdi = 0, rsi = 0, rdx = 0;
  if (vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id) != VMI_SUCCESS) {
    log_error("EVENT_NETFILTER_HOOK_WRITE: Failed to get RDI for vCPU %u",
              event->vcpu_id);
    return VMI_EVENT_INVALID;
  }
  if (vmi_get_vcpureg(vmi, &rsi, RSI, event->vcpu_id) != VMI_SUCCESS) {
    log_error("EVENT_NETFILTER_HOOK_WRITE: Failed to get RSI for vCPU %u",
              event->vcpu_id);
    return VMI_EVENT_INVALID;
  }
  if (vmi_get_vcpureg(vmi, &rdx, RDX, event->vcpu_id) != VMI_SUCCESS) {
    log_error("EVENT_NETFILTER_HOOK_WRITE: Failed to get RDX for vCPU %u",
              event->vcpu_id);
    return VMI_EVENT_INVALID;
  }

  log_debug("EVENT_NETFILTER_HOOK_WRITE: %s @0x%" PRIx64 " net=0x%" PRIx64
           " ops=0x%" PRIx64 " n=%llu",
           ctx->symname ? ctx->symname : "nf_register_net_hook", ctx->kaddr,
           (uint64_t)rdi, (uint64_t)rsi, (unsigned long long)rdx);

  // Restore original byte
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &ctx->orig) != VMI_SUCCESS) {
    log_error(
        "EVENT_NETFILTER_HOOK_WRITE: Failed to restore original byte at "
        "0x%" PRIx64,
        (uint64_t)ctx->kaddr);
    return VMI_EVENT_INVALID;
  }

  memset(&ctx->ss_evt, 0, sizeof(ctx->ss_evt));
  ctx->ss_evt.version = VMI_EVENTS_VERSION;
  ctx->ss_evt.type = VMI_EVENT_SINGLESTEP;
  ctx->ss_evt.callback = event_netfilter_hook_write_ss_callback;
  ctx->ss_evt.data = ctx;
  ctx->ss_evt.ss_event.enable = 1;

  if (vmi_register_event(vmi, &ctx->ss_evt) != VMI_SUCCESS) {
    log_warn(
        "EVENT_NETFILTER_HOOK_WRITE: Failed to register SINGLESTEP event. "
        "Breakpoint will not be re-armed");
    return VMI_EVENT_RESPONSE_NONE;
  }

  if (vmi_toggle_single_step_vcpu(vmi, &ctx->ss_evt, event->vcpu_id, true) !=
      VMI_SUCCESS) {
    log_warn(
        "EVENT_NETFILTER_HOOK_WRITE: Failed to enable single-step on vCPU %u. "
        "Breakpoint will not be re-armed",
        event->vcpu_id);
  }

  log_debug("EVENT_NETFILTER_HOOK_WRITE: Single-step enabled on vCPU %u",
           event->vcpu_id);

  log_vcpu_state(vmi, event->vcpu_id, ctx->kaddr, "CB exit");

  return VMI_EVENT_RESPONSE_NONE;
}