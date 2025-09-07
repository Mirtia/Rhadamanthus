#include "event_callbacks/ebpf_probe.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
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
 * @return void
 */
static void extract_kprobe_info(vmi_instance_t vmi, uint32_t vcpu_id) {
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

  // Read target symbol name
  addr_t symbol_ptr = 0;
  // TODO: Replace 0x8 with proper offset from offsets.h (pahole)
  if (vmi_read_addr_va(vmi, kprobe_ptr + 0x8, 0, &symbol_ptr) == VMI_SUCCESS &&
      symbol_ptr) {
    char* symbol_name = vmi_read_str_va(vmi, symbol_ptr, 0);
    if (symbol_name) {
      log_debug("EVENT_EBPF_PROBE: Target Symbol: %s", symbol_name);

      // Check for commonly targeted functions by rootkits
      if (strstr(symbol_name, "sys_open") ||
          strstr(symbol_name, "sys_openat") ||
          strstr(symbol_name, "do_sys_open") ||
          strstr(symbol_name, "vfs_open")) {
        log_warn("EVENT_EBPF_PROBE: File operation hook detected (%s)",
                 symbol_name);
      } else if (strstr(symbol_name, "sys_getdents") ||
                 strstr(symbol_name, "filldir")) {
        log_warn("EVENT_EBPF_PROBE: Directory listing hook detected (%s)",
                 symbol_name);
      } else if (strstr(symbol_name, "sys_kill") ||
                 strstr(symbol_name, "sys_tkill")) {
        log_warn("EVENT_EBPF_PROBE: Process killing hook detected (%s)",
                 symbol_name);
      } else if (strstr(symbol_name, "tcp") || strstr(symbol_name, "inet") ||
                 strstr(symbol_name, "sock")) {
        log_warn("EVENT_EBPF_PROBE: Network operation hook detected (%s)",
                 symbol_name);
      } else if (strstr(symbol_name, "sys_delete_module") ||
                 strstr(symbol_name, "sys_init_module")) {
        log_warn("EVENT_EBPF_PROBE: Module operation hook detected (%s)",
                 symbol_name);
      }

      g_free(symbol_name);
    }
  }

  // Read target address
  addr_t target_addr = 0;
  if (vmi_read_addr_va(vmi, kprobe_ptr + 0x0, 0, &target_addr) == VMI_SUCCESS &&
      target_addr) {
    log_debug("EVENT_EBPF_PROBE: Target Address: 0x%" PRIx64, target_addr);
  }
}

/**
 * @brief Extract BPF program attachment information.
 * 
 * Analyzes BPF program attachment calls to determine attachment type
 * and potential security implications.
 * 
 * @param vmi VMI instance
 * @param vcpu_id VCPU identifier
 * @param func_name Function name being called
 * @return void
 */
static void extract_bpf_attach_info(vmi_instance_t vmi, uint32_t vcpu_id,
                                    const char* func_name) {
  registers_t regs;
  if (vmi_get_vcpuregs(vmi, &regs, vcpu_id) != VMI_SUCCESS) {
    log_debug("EVENT_EBPF_PROBE: Failed to get CPU registers for VCPU %u",
             vcpu_id);
    return;
  }

  if (strstr(func_name, "bpf_prog_attach")) {
    uint32_t prog_fd = (uint32_t)regs.x86.rdi;
    uint32_t attach_type = (uint32_t)regs.x86.rdx;

    log_debug("EVENT_EBPF_PROBE: Program FD: %u, Attach Type: %u", prog_fd,
             attach_type);

    if (attach_type == 1 || attach_type == 2) {
      log_warn(
          "EVENT_EBPF_PROBE: Network traffic interception capability detected");
    } else if (attach_type >= 14 && attach_type <= 17) {
      log_warn(
          "EVENT_EBPF_PROBE: Container/cgroup manipulation capability "
          "detected");
    }

  } else if (strstr(func_name, "bpf_raw_tracepoint")) {
    addr_t name_ptr = regs.x86.rdi;
    if (name_ptr) {
      char* tp_name = vmi_read_str_va(vmi, name_ptr, 0);
      if (tp_name) {
        log_debug("EVENT_EBPF_PROBE: Tracepoint: %s", tp_name);

        if (strstr(tp_name, "sys_enter") || strstr(tp_name, "sys_exit")) {
          log_warn("EVENT_EBPF_PROBE: System call tracing capability detected");
        } else if (strstr(tp_name, "sched_process")) {
          log_warn("EVENT_EBPF_PROBE: Process monitoring capability detected");
        } else if (strstr(tp_name, "net_dev") || strstr(tp_name, "sock")) {
          log_warn("EVENT_EBPF_PROBE: Network monitoring capability detected");
        }

        g_free(tp_name);
      }
    }
  }
}

/**
 * @brief Single-step callback for eBPF probe monitoring.
 * 
 * Re-arms the breakpoint after the original instruction has executed.
 * Follows the established single-step pattern used by io_uring and netfilter.
 * 
 * @param vmi VMI instance
 * @param event Single-step event
 * @return event_response_t VMI_EVENT_RESPONSE_NONE
 */
static event_response_t event_ebpf_probe_ss_callback(vmi_instance_t vmi,
                                                     vmi_event_t* event) {

  ebpf_probe_ctx_t* ctx = (ebpf_probe_ctx_t*)event->data;
  if (!ctx) {
    log_error("EVENT_EBPF_PROBE: NULL context in SS handler.");
    return VMI_EVENT_INVALID;
  }

  // Re-arm the breakpoint by writing INT3 back
  uint8_t int3 = 0xCC;
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &int3) != VMI_SUCCESS) {
    log_warn("EVENT_EBPF_PROBE: Failed to re-arm breakpoint at 0x%" PRIx64,
             ctx->kaddr);
  }

  // Disable single-step on this VCPU
  if (vmi_toggle_single_step_vcpu(vmi, event, event->vcpu_id, false) !=
      VMI_SUCCESS) {
    log_warn("EVENT_EBPF_PROBE: Failed to disable single-step on VCPU %u",
             event->vcpu_id);
  }

  log_debug("EVENT_EBPF_PROBE: Breakpoint re-armed on vCPU %u", event->vcpu_id);

  log_vcpu_state(vmi, event->vcpu_id, ctx->kaddr, "SS exit");
  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t event_ebpf_probe_callback(vmi_instance_t vmi,
                                           vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    log_error("EVENT_EBPF_PROBE: Invalid arguments to eBPF probe callback.");
    return VMI_EVENT_INVALID;
  }

  ebpf_probe_ctx_t* ctx = (ebpf_probe_ctx_t*)event->data;
  if (!ctx) {
    log_error("EVENT_EBPF_PROBE: NULL context in INT3 handler.");
    return VMI_EVENT_INVALID;
  }

  if (ctx->kaddr == 0) {
    log_error("EVENT_EBPF_PROBE: Invalid kaddr in context.");
    return VMI_EVENT_INVALID;
  }

  event->interrupt_event.reinject = 0;
  event->interrupt_event.insn_length = 0;

  uint32_t vcpu_id = event->vcpu_id;
  addr_t rip = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    log_error("EVENT_EBPF_PROBE: Failed to get RIP for VCPU %u", vcpu_id);
    return VMI_EVENT_INVALID;
  }

  vmi_pid_t pid = 0;
  if (vmi_dtb_to_pid(vmi, event->x86_regs->cr3, &pid) != VMI_SUCCESS) {
    log_debug("EVENT_EBPF_PROBE: Could not determine PID for CR3 0x%" PRIx64,
              event->x86_regs->cr3);
    pid = 0;
  }

  log_warn(
      "EVENT_EBPF_PROBE: eBPF probe insertion detected | "
      "VCPU: %u RIP: 0x%" PRIx64 " PID: %u Function: %s Address: 0x%" PRIx64,
      vcpu_id, (uint64_t)rip, pid, ctx->symname ? ctx->symname : "unknown",
      ctx->kaddr);

  // Extract function-specific details
  if (ctx->symname && (strstr(ctx->symname, "register_kprobe") ||
                       strstr(ctx->symname, "register_kretprobe"))) {
    log_debug("EVENT_EBPF_PROBE: Type - Kernel probe registration");
    extract_kprobe_info(vmi, vcpu_id);
  } else if (ctx->symname && strstr(ctx->symname, "register_uprobe")) {
    log_debug("EVENT_EBPF_PROBE: Type - User-space probe registration");
    registers_t regs;
    if (vmi_get_vcpuregs(vmi, &regs, vcpu_id) == VMI_SUCCESS) {
      uint64_t file_offset = regs.x86.rsi;
      log_debug("EVENT_EBPF_PROBE: File Offset: 0x%" PRIx64, file_offset);
    }
  } else if (ctx->symname && strstr(ctx->symname, "bpf_")) {
    log_debug("EVENT_EBPF_PROBE: Type - eBPF program attachment");
    extract_bpf_attach_info(vmi, vcpu_id, ctx->symname);
  } else if (ctx->symname && strstr(ctx->symname, "tracepoint")) {
    log_debug("EVENT_EBPF_PROBE: Type - Tracepoint probe registration");
  }

  // Restore original byte
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &ctx->orig) != VMI_SUCCESS) {
    log_error("EVENT_EBPF_PROBE: Failed to restore original byte at 0x%" PRIx64,
              ctx->kaddr);
    return VMI_EVENT_INVALID;
  }

  memset(&ctx->ss_evt, 0, sizeof(ctx->ss_evt));
  ctx->ss_evt.version = VMI_EVENTS_VERSION;
  ctx->ss_evt.type = VMI_EVENT_SINGLESTEP;
  ctx->ss_evt.callback = event_ebpf_probe_ss_callback;
  ctx->ss_evt.data = ctx;
  ctx->ss_evt.ss_event.enable = 1;

  if (vmi_register_event(vmi, &ctx->ss_evt) != VMI_SUCCESS) {
    log_warn(
        "EVENT_EBPF_PROBE: Failed to register SINGLESTEP event. "
        "Breakpoint will not be re-armed.");
    return VMI_EVENT_RESPONSE_NONE;
  }

  if (vmi_toggle_single_step_vcpu(vmi, &ctx->ss_evt, vcpu_id, true) !=
      VMI_SUCCESS) {
    log_warn(
        "EVENT_EBPF_PROBE: Failed to enable single-step on vCPU %u. "
        "Breakpoint will not be re-armed.",
        vcpu_id);
  }

  log_debug("EVENT_EBPF_PROBE: Single-step enabled on vCPU %u.", vcpu_id);

  log_vcpu_state(vmi, vcpu_id, ctx->kaddr, "CB exit");

  return VMI_EVENT_RESPONSE_NONE;
}