#include "event_callbacks/kprobe.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/responses/kprobe_response.h"
#include "offsets.h"
#include "utils.h"

/**
 * @brief Extract kprobe registration information from function arguments.
 * 
 * Analyzes the kprobe structure to determine what kernel function is being
 * hooked and evaluates potential security implications.
 * 
 * @param vmi VMI instance
 * @param vcpu_id VCPU identifier
 * @param target_symbol_out Output parameter for target symbol name
 * @param target_addr_out Output parameter for target address
 * @return void
 */
static void extract_kprobe_info(vmi_instance_t vmi, uint32_t vcpu_id,
                                char** target_symbol_out,
                                addr_t* target_addr_out) {
  if (target_symbol_out)
    *target_symbol_out = NULL;
  if (target_addr_out)
    *target_addr_out = 0;

  registers_t regs;
  if (vmi_get_vcpuregs(vmi, &regs, vcpu_id) != VMI_SUCCESS) {
    log_debug("Failed to get CPU registers for VCPU %u", vcpu_id);
    return;
  }

  addr_t kprobe_ptr = regs.x86.rdi;
  if (!kprobe_ptr) {
    log_debug("Kprobe pointer is NULL");
    return;
  }

  // Read target symbol name using proper offset from offsets.h
  addr_t symbol_ptr = 0;
  if (vmi_read_addr_va(vmi, kprobe_ptr + LINUX_KPROBE_SYMBOL_NAME_OFFSET, 0,
                       &symbol_ptr) == VMI_SUCCESS &&
      symbol_ptr) {
    char* symbol_name = vmi_read_str_va(vmi, symbol_ptr, 0);
    if (symbol_name) {
      log_debug("EVENT_KPROBE: Target Symbol: %s", symbol_name);

      // Check for commonly targeted functions by rootkits
      if (strstr(symbol_name, "sys_open") ||
          strstr(symbol_name, "sys_openat") ||
          strstr(symbol_name, "do_sys_open") ||
          strstr(symbol_name, "vfs_open")) {
        log_warn("EVENT_KPROBE: File operation hook detected (%s)",
                 symbol_name);
      } else if (strstr(symbol_name, "sys_getdents") ||
                 strstr(symbol_name, "filldir")) {
        log_warn("EVENT_KPROBE: Directory listing hook detected (%s)",
                 symbol_name);
      } else if (strstr(symbol_name, "sys_kill") ||
                 strstr(symbol_name, "sys_tkill")) {
        log_warn("EVENT_KPROBE: Process killing hook detected (%s)",
                 symbol_name);
      } else if (strstr(symbol_name, "tcp") || strstr(symbol_name, "inet") ||
                 strstr(symbol_name, "sock")) {
        log_warn("EVENT_KPROBE: Network operation hook detected (%s)",
                 symbol_name);
      } else if (strstr(symbol_name, "sys_delete_module") ||
                 strstr(symbol_name, "sys_init_module")) {
        log_warn("EVENT_KPROBE: Module operation hook detected (%s)",
                 symbol_name);
      }

      if (target_symbol_out) {
        *target_symbol_out = g_strdup(symbol_name);
      }
      g_free(symbol_name);
    }
  }

  // Read target address using proper offset from offsets.h
  addr_t target_addr = 0;
  if (vmi_read_addr_va(vmi, kprobe_ptr + LINUX_KPROBE_ADDR_OFFSET, 0,
                       &target_addr) == VMI_SUCCESS &&
      target_addr) {
    log_debug("EVENT_KPROBE: Target Address: 0x%" PRIx64, target_addr);
    if (target_addr_out) {
      *target_addr_out = target_addr;
    }
  }
}

/**
 * @brief Single-step callback for kprobe monitoring.
 * 
 * Re-arms the breakpoint after the original instruction has executed.
 * Follows the established single-step pattern used by io_uring and netfilter.
 * 
 * @param vmi VMI instance
 * @param event Single-step event
 * @return event_response_t VMI_EVENT_RESPONSE_NONE
 */
static event_response_t event_kprobe_ss_callback(vmi_instance_t vmi,
                                                 vmi_event_t* event) {

  kprobe_ctx_t* ctx = (kprobe_ctx_t*)event->data;
  if (!ctx) {
    log_error("EVENT_KPROBE: NULL context in SS handler.");
    return VMI_EVENT_INVALID;
  }

  // Additional safety check - ensure kaddr is valid
  if (ctx->kaddr == 0) {
    log_warn("EVENT_KPROBE: Invalid kaddr in SS handler, skipping re-arm.");
    return VMI_EVENT_RESPONSE_NONE;
  }

  // Re-arm the breakpoint by writing INT3 back
  uint8_t int3 = 0xCC;
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &int3) != VMI_SUCCESS) {
    log_warn("EVENT_KPROBE: Failed to re-arm breakpoint at 0x%" PRIx64,
             ctx->kaddr);
  }

  // Disable single-step on this VCPU
  if (vmi_toggle_single_step_vcpu(vmi, event, event->vcpu_id, false) !=
      VMI_SUCCESS) {
    log_warn("EVENT_KPROBE: Failed to disable single-step on VCPU %u",
             event->vcpu_id);
  }

  // Note: We don't clear the single-step event here as it's automatically
  // cleaned up by LibVMI when the event completes

  log_debug("EVENT_KPROBE: Breakpoint re-armed on vCPU %u", event->vcpu_id);

  log_vcpu_state(vmi, event->vcpu_id, ctx->kaddr, "SS exit");
  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t event_kprobe_callback(vmi_instance_t vmi, vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_interrupt(
        "kprobe", INTERRUPT_KPROBE, INVALID_ARGUMENTS,
        "Invalid arguments to kprobe callback.");
  }

  kprobe_ctx_t* ctx = (kprobe_ctx_t*)event->data;
  if (!ctx) {
    return log_error_and_queue_response_interrupt(
        "kprobe", INTERRUPT_KPROBE, INVALID_ARGUMENTS,
        "NULL context in INT3 handler.");
  }

  if (ctx->kaddr == 0) {
    return log_error_and_queue_response_interrupt("kprobe", INTERRUPT_KPROBE,
                                                  INVALID_ARGUMENTS,
                                                  "Invalid kaddr in context.");
  }

  event->interrupt_event.reinject = 0;
  event->interrupt_event.insn_length = 0;

  uint32_t vcpu_id = event->vcpu_id;
  uint64_t rip = 0, cr3 = 0, rsp = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "kprobe", INTERRUPT_KPROBE, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "kprobe", INTERRUPT_KPROBE, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "kprobe", INTERRUPT_KPROBE, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
  }

  vmi_pid_t pid = 0;
  if (vmi_dtb_to_pid(vmi, event->x86_regs->cr3, &pid) != VMI_SUCCESS) {
    log_debug("EVENT_KPROBE: Could not determine PID for CR3 0x%" PRIx64,
              event->x86_regs->cr3);
    pid = 0;
  }

  log_warn(
      "EVENT_KPROBE: Kernel probe insertion detected | "
      "VCPU: %u RIP: 0x%" PRIx64 " PID: %u Function: %s Address: 0x%" PRIx64,
      vcpu_id, (uint64_t)rip, pid, ctx->symname ? ctx->symname : "unknown",
      ctx->kaddr);

  char* target_symbol = NULL;
  addr_t target_addr = 0;
  const char* probe_type = "unknown";

  if (ctx->symname && (strstr(ctx->symname, "register_kprobe") ||
                       strstr(ctx->symname, "register_kretprobe"))) {
    log_debug("EVENT_KPROBE: Type - Kernel probe registration");
    probe_type = "kprobe";
    extract_kprobe_info(vmi, vcpu_id, &target_symbol, &target_addr);
  } else if (ctx->symname && strstr(ctx->symname, "register_uprobe")) {
    log_debug("EVENT_KPROBE: Type - User-space probe registration");
    probe_type = "uprobe";
    registers_t regs;
    if (vmi_get_vcpuregs(vmi, &regs, vcpu_id) == VMI_SUCCESS) {
      uint64_t file_offset = regs.x86.rsi;
      log_debug("EVENT_KPROBE: File Offset: 0x%" PRIx64, file_offset);
    }
  } else if (ctx->symname &&
             strstr(ctx->symname, "tracepoint_probe_register")) {
    log_debug("EVENT_KPROBE: Type - Tracepoint probe registration");
    probe_type = "tracepoint";
  }

  kprobe_data_t* kprobe_data =
      kprobe_data_new(vcpu_id, rip, rsp, cr3, pid, ctx->kaddr, ctx->symname,
                      probe_type, target_symbol, target_addr);

  if (target_symbol)
    g_free(target_symbol);

  if (!kprobe_data) {
    return log_error_and_queue_response_interrupt(
        "kprobe", INTERRUPT_KPROBE, MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for kprobe data.");
  }

  // Restore original byte - this is critical for proper instruction execution
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &ctx->orig) != VMI_SUCCESS) {
    log_error("EVENT_KPROBE: Failed to restore original byte at 0x%" PRIx64,
              ctx->kaddr);
    kprobe_data_free(kprobe_data);
    return VMI_EVENT_INVALID;
  }

  memset(&ctx->ss_evt, 0, sizeof(ctx->ss_evt));
  ctx->ss_evt.version = VMI_EVENTS_VERSION;
  ctx->ss_evt.type = VMI_EVENT_SINGLESTEP;
  ctx->ss_evt.callback = event_kprobe_ss_callback;
  ctx->ss_evt.data = ctx;
  ctx->ss_evt.ss_event.enable = 1;

  if (vmi_register_event(vmi, &ctx->ss_evt) != VMI_SUCCESS) {
    log_warn(
        "EVENT_KPROBE: Failed to register SINGLESTEP event. "
        "Breakpoint will not be re-armed.");
    return log_success_and_queue_response_interrupt(
        "kprobe", INTERRUPT_KPROBE, (void*)kprobe_data,
        (void (*)(void*))kprobe_data_free);
  }

  if (vmi_toggle_single_step_vcpu(vmi, &ctx->ss_evt, vcpu_id, true) !=
      VMI_SUCCESS) {
    log_warn(
        "EVENT_KPROBE: Failed to enable single-step on vCPU %u. "
        "Breakpoint will not be re-armed.",
        vcpu_id);
  }

  log_debug("EVENT_KPROBE: Single-step enabled on vCPU %u.", vcpu_id);

  log_vcpu_state(vmi, vcpu_id, ctx->kaddr, "CB exit");

  return log_success_and_queue_response_interrupt(
      "kprobe", INTERRUPT_KPROBE, (void*)kprobe_data,
      (void (*)(void*))kprobe_data_free);
}
