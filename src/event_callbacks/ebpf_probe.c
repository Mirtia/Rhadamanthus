#include "event_callbacks/ebpf_probe.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>

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
        log_warn("EVENT_EBPF_PROBE: File operation hook detected");
      } else if (strstr(symbol_name, "sys_getdents") ||
                 strstr(symbol_name, "filldir")) {
        log_warn("EVENT_EBPF_PROBE: Directory listing hook detected");
      } else if (strstr(symbol_name, "sys_kill") ||
                 strstr(symbol_name, "sys_tkill")) {
        log_warn("EVENT_EBPF_PROBE: Process killing hook detected");
      } else if (strstr(symbol_name, "tcp") || strstr(symbol_name, "inet") ||
                 strstr(symbol_name, "sock")) {
        log_warn("EVENT_EBPF_PROBE: Network operation hook detected");
      } else if (strstr(symbol_name, "sys_delete_module") ||
                 strstr(symbol_name, "sys_init_module")) {
        log_warn("EVENT_EBPF_PROBE: Module operation hook detected");
      }

      g_free(symbol_name);
    }
  }

  // Read target address
  addr_t target_addr = 0;
  if (vmi_read_addr_va(vmi, kprobe_ptr + 0x0, 0, &target_addr) == VMI_SUCCESS &&
      target_addr) {
    log_info("EVENT_EBPF_PROBE: Target Address: 0x%" PRIx64, target_addr);
  }
}

static void extract_bpf_attach_info(vmi_instance_t vmi, uint32_t vcpu_id,
                                    const char* func_name) {
  registers_t regs;
  if (vmi_get_vcpuregs(vmi, &regs, vcpu_id) != VMI_SUCCESS) {
    log_warn("EVENT_EBPF_PROBE: Failed to get CPU registers for VCPU %u",
             vcpu_id);
    return;
  }

  if (strstr(func_name, "bpf_prog_attach")) {
    uint32_t prog_fd = (uint32_t)regs.x86.rdi;
    uint32_t attach_type = (uint32_t)regs.x86.rdx;

    log_warn("EVENT_EBPF_PROBE: Program FD: %u", prog_fd);
    log_warn("EVENT_EBPF_PROBE: Attach Type: %u", attach_type);

    if (attach_type == 1 || attach_type == 2) {
      log_warn("EVENT_EBPF_PROBE: Network traffic interception capability");
    } else if (attach_type >= 14 && attach_type <= 17) {
      log_warn("EVENT_EBPF_PROBE: Container/cgroup manipulation capability");
    }

  } else if (strstr(func_name, "bpf_raw_tracepoint")) {
    addr_t name_ptr = regs.x86.rdi;
    if (name_ptr) {
      char* tp_name = vmi_read_str_va(vmi, name_ptr, 0);
      if (tp_name) {
        log_warn("EVENT_EBPF_PROBE: Tracepoint: %s", tp_name);

        if (strstr(tp_name, "sys_enter") || strstr(tp_name, "sys_exit")) {
          log_warn("EVENT_EBPF_PROBE: System call tracing capability");
        } else if (strstr(tp_name, "sched_process")) {
          log_warn("EVENT_EBPF_PROBE: Process monitoring capability");
        } else if (strstr(tp_name, "net_dev") || strstr(tp_name, "sock")) {
          log_warn("EVENT_EBPF_PROBE: Network monitoring capability");
        }

        g_free(tp_name);
      }
    }
  }
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
    log_error("EVENT_EBPF_PROBE: Missing context data.");
    return VMI_EVENT_INVALID;
  }

  uint32_t vcpu_id = event->vcpu_id;
  addr_t rip = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    log_warn("EVENT_EBPF_PROBE: Failed to get RIP for VCPU %u", vcpu_id);
  }

  vmi_pid_t pid = 0;
  if (vmi_dtb_to_pid(vmi, event->x86_regs->cr3, &pid) != VMI_SUCCESS) {
    pid = 0;
  }

  log_warn(
      "EVENT_EBPF_PROBE: eBPF probe insertion detected | "
      "VCPU: %u RIP: 0x%" PRIx64 " PID: %u Function: %s Address: 0x%" PRIx64,
      vcpu_id, (uint64_t)rip, pid, ctx->symname, ctx->kaddr);

  // Extract function-specific details
  if (strstr(ctx->symname, "register_kprobe") ||
      strstr(ctx->symname, "register_kretprobe")) {
    log_warn("EVENT_EBPF_PROBE: Type - Kernel probe registration");
    extract_kprobe_info(vmi, vcpu_id);
  } else if (strstr(ctx->symname, "register_uprobe")) {
    log_warn("EVENT_EBPF_PROBE: Type - User-space probe registration");
    registers_t regs;
    if (vmi_get_vcpuregs(vmi, &regs, vcpu_id) == VMI_SUCCESS) {
      uint64_t file_offset = regs.x86.rsi;
      log_warn("EVENT_EBPF_PROBE: File Offset: 0x%" PRIx64, file_offset);
    }
  } else if (strstr(ctx->symname, "bpf_")) {
    log_warn("EVENT_EBPF_PROBE: Type - eBPF program attachment");
    extract_bpf_attach_info(vmi, vcpu_id, ctx->symname);
  } else if (strstr(ctx->symname, "tracepoint")) {
    log_warn("EVENT_EBPF_PROBE: Type - Tracepoint probe registration");
  }

  // Restore original instruction
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &ctx->orig) != VMI_SUCCESS) {
    log_error("EVENT_EBPF_PROBE: Failed to restore original byte at 0x%" PRIx64,
              ctx->kaddr);
  }

  // Enable single-step
  if (vmi_toggle_single_step_vcpu(vmi, event, vcpu_id, 1) != VMI_SUCCESS) {
    log_error("EVENT_EBPF_PROBE: Failed to enable single-step for VCPU %u",
              vcpu_id);
  }

  return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t ebpf_probe_singlestep_callback(vmi_instance_t vmi,
                                                       vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    log_error("EVENT_EBPF_PROBE: Invalid arguments to single-step callback.");
    return VMI_EVENT_INVALID;
  }

  ebpf_probe_ctx_t* ctx = (ebpf_probe_ctx_t*)event->data;
  if (!ctx) {
    log_error(
        "EVENT_EBPF_PROBE: Missing context data in single-step callback.");
    return VMI_EVENT_INVALID;
  }

  uint32_t vcpu_id = event->vcpu_id;

  // Re-plant INT3 breakpoint
  uint8_t cc = 0xCC;
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &cc) != VMI_SUCCESS) {
    log_error("EVENT_EBPF_PROBE: Failed to re-plant INT3 at 0x%" PRIx64,
              ctx->kaddr);
  }

  // Disable single-step
  if (vmi_toggle_single_step_vcpu(vmi, event, vcpu_id, 0) != VMI_SUCCESS) {
    log_error("EVENT_EBPF_PROBE: Failed to disable single-step for VCPU %u",
              vcpu_id);
  }

  return VMI_EVENT_RESPONSE_NONE;
}

static vmi_event_t* create_event_ebpf_probe(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("EVENT_EBPF_PROBE: Invalid VMI instance at event registration.");
    return NULL;
  }

  const char* probe_functions[] = {"register_kprobe",
                                   "register_kretprobe",
                                   "register_uprobe",
                                   "bpf_prog_attach",
                                   "bpf_raw_tracepoint_open",
                                   "tracepoint_probe_register",
                                   NULL};

  for (int i = 0; probe_functions[i] != NULL; i++) {
    addr_t func_addr = 0;
    if (vmi_translate_ksym2v(vmi, probe_functions[i], &func_addr) !=
            VMI_SUCCESS ||
        !func_addr) {
      log_debug("EVENT_EBPF_PROBE: Symbol not found: %s", probe_functions[i]);
      continue;
    }

    uint8_t orig = 0;
    if (vmi_read_8_va(vmi, func_addr, 0, &orig) != VMI_SUCCESS) {
      log_warn("EVENT_EBPF_PROBE: Failed reading byte at %s @0x%" PRIx64,
               probe_functions[i], func_addr);
      continue;
    }

    uint8_t cc = 0xCC;
    if (vmi_write_8_va(vmi, func_addr, 0, &cc) != VMI_SUCCESS) {
      log_warn("EVENT_EBPF_PROBE: Failed planting INT3 at %s @0x%" PRIx64,
               probe_functions[i], func_addr);
      continue;
    }

    ebpf_probe_ctx_t* ctx = (ebpf_probe_ctx_t*)g_malloc(sizeof(*ctx));
    if (!ctx) {
      log_error("EVENT_EBPF_PROBE: Failed to allocate probe context");
      vmi_write_8_va(vmi, func_addr, 0, &orig);
      continue;
    }
    ctx->kaddr = func_addr;
    ctx->orig = orig;
    ctx->symname = probe_functions[i];

    // Interrupt (INT3) event
    vmi_event_t* intr_event = (vmi_event_t*)g_malloc(sizeof(*intr_event));
    if (!intr_event) {
      log_error("EVENT_EBPF_PROBE: Failed to allocate interrupt vmi_event_t");
      vmi_write_8_va(vmi, func_addr, 0, &orig);
      g_free(ctx);
      continue;
    }

    memset(intr_event, 0, sizeof(*intr_event));
    intr_event->version = VMI_EVENTS_VERSION;
    intr_event->type = VMI_EVENT_INTERRUPT;
    intr_event->interrupt_event.intr = INT3;  // software breakpoint
    intr_event->interrupt_event.reinject =
        -1;  // leave reinjection policy unchanged
    intr_event->callback = event_ebpf_probe_callback;
    intr_event->data = ctx;

    if (vmi_register_event(vmi, intr_event) != VMI_SUCCESS) {
      log_warn("EVENT_EBPF_PROBE: Failed to register INTERRUPT(INT3) for %s",
               probe_functions[i]);
      vmi_write_8_va(vmi, func_addr, 0, &orig);
      g_free(ctx);
      g_free(intr_event);
      continue;
    }

    // Single-step event: re-plant INT3 after one instruction
    vmi_event_t* ss_event = (vmi_event_t*)g_malloc(sizeof(*ss_event));
    if (!ss_event) {
      log_error("EVENT_EBPF_PROBE: Failed to allocate single-step vmi_event_t");
      vmi_write_8_va(vmi, func_addr, 0, &orig);
      g_free(ctx);
      g_free(intr_event);
      continue;
    }

    memset(ss_event, 0, sizeof(*ss_event));
    ss_event->version = VMI_EVENTS_VERSION;
    ss_event->type = VMI_EVENT_SINGLESTEP;
    ss_event->callback = ebpf_probe_singlestep_callback;
    ss_event->data = ctx;

    if (vmi_register_event(vmi, ss_event) != VMI_SUCCESS) {
      log_warn("EVENT_EBPF_PROBE: Failed to register SINGLESTEP for %s",
               probe_functions[i]);
      vmi_write_8_va(vmi, func_addr, 0, &orig);
      g_free(ctx);
      g_free(intr_event);
      g_free(ss_event);
      continue;
    }

    log_info("EVENT_EBPF_PROBE: Monitoring enabled on %s @0x%" PRIx64,
             probe_functions[i], func_addr);
    return intr_event;
  }

  log_warn("EVENT_EBPF_PROBE: No probe registration symbols could be hooked");
  return NULL;
}
