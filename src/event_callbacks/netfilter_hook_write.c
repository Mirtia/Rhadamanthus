#include "event_callbacks/netfilter_hook_write.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "event_handler.h"
#include "offsets.h"

/**
 * @brief No-op free callback to pair with vmi_clear_event.
 */
static void vmi_event_free_noop() {
  log_debug("(҂ `з´) ︻╦̵̵̿╤──");
}

static event_response_t event_netfilter_hook_write_ss_callback(
    vmi_instance_t vmi, vmi_event_t* event) {
  nf_bp_ctx_t* ctx = (nf_bp_ctx_t*)event->data;

  uint8_t val = 0xCC;
  (void)vmi_write_8_va(vmi, ctx->kaddr, 0, &val);

  reg_t rflags = 0;
  (void)vmi_get_vcpureg(vmi, &rflags, RFLAGS, event->vcpu_id);
  rflags &= ~(1ULL << 8);
  (void)vmi_set_vcpureg(vmi, rflags, RFLAGS, event->vcpu_id);

  // One-shot SINGLESTEP event
  vmi_clear_event(vmi, event, vmi_event_free_noop);
  return VMI_EVENT_RESPONSE_NONE;
}

/**
 * @brief INT3 entry callback: logs args, restores first byte, enables TF, rewinds RIP, registers SS.
 */
event_response_t event_netfilter_hook_write_callback(vmi_instance_t vmi,
                                                     vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    log_error("EVENT_NETFILTER_HOOK_WRITE: Invalid arguments to callback.");
  }
  nf_bp_ctx_t* ctx = (nf_bp_ctx_t*)event->data;

  // Expected calling convention (x86_64 SysV):
  //   RDI = struct net *net
  //   RSI = const struct nf_hook_ops *ops
  //   RDX = size_t n   (only for nf_register_net_hooks)
  reg_t rdi = 0, rsi = 0, rdx = 0, rip = 0, rflags = 0;
  (void)vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
  (void)vmi_get_vcpureg(vmi, &rsi, RSI, event->vcpu_id);
  (void)vmi_get_vcpureg(vmi, &rdx, RDX, event->vcpu_id);

  log_info("%s ENTER @0x%" PRIx64 " net=0x%" PRIx64 " ops=0x%" PRIx64 " n=%llu",
           ctx->symname ? ctx->symname : "nf_register_net_hook",
           (uint64_t)ctx->kaddr, (uint64_t)rdi, (uint64_t)rsi,
           (unsigned long long)rdx);

  uint8_t val = ctx->orig;
  (void)vmi_write_8_va(vmi, ctx->kaddr, 0, &val);

  // Enable TF and rewind RIP by 1 (INT3 advanced RIP by 1)
  (void)vmi_get_vcpureg(vmi, &rip, RIP, event->vcpu_id);
  (void)vmi_get_vcpureg(vmi, &rflags, RFLAGS, event->vcpu_id);
  if (rip) {
    (void)vmi_set_vcpureg(vmi, rip - 1, RIP, event->vcpu_id);
  }
  (void)vmi_set_vcpureg(vmi, rflags | (1ULL << 8), RFLAGS,
                        event->vcpu_id);  // TF=1

  // Register one-shot SINGLESTEP to re-arm INT3 and clear TF
  if (ctx->ss_evt.callback == NULL) {
    memset(&ctx->ss_evt, 0, sizeof(ctx->ss_evt));
    ctx->ss_evt.version = VMI_EVENTS_VERSION;
    ctx->ss_evt.type = VMI_EVENT_SINGLESTEP;
    ctx->ss_evt.callback = event_netfilter_hook_write_ss_callback;
    ctx->ss_evt.data = ctx;
  }
  if (vmi_register_event(vmi, &ctx->ss_evt) != VMI_SUCCESS) {
    log_warn("%s: failed to register SINGLESTEP; INT3 may not be re-armed.",
             ctx->symname ? ctx->symname : "nf_register_net_hook");
  }

  return VMI_EVENT_RESPONSE_NONE;
}