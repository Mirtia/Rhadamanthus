#include "event_callbacks/ebpf_tracepoint.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/responses/ebpf_tracepoint_response.h"
#include "offsets.h"
#include "utils.h"

/**
 * @brief Extract eBPF tracepoint information from function arguments.
 * 
 * Analyzes eBPF program attachment calls to determine attachment type
 * and potential security implications.
 * 
 * @param vmi VMI instance
 * @param vcpu_id VCPU identifier
 * @param func_name Function name being called
 * @param attach_type_out Output parameter for attach type
 * @param tracepoint_name_out Output parameter for tracepoint name
 * @return void
 */
static void extract_ebpf_tracepoint_info(vmi_instance_t vmi, uint32_t vcpu_id,
                                         const char* func_name,
                                         uint32_t* attach_type_out,
                                         char** tracepoint_name_out) {
  if (attach_type_out)
    *attach_type_out = 0;
  if (tracepoint_name_out)
    *tracepoint_name_out = NULL;

  registers_t regs;
  if (vmi_get_vcpuregs(vmi, &regs, vcpu_id) != VMI_SUCCESS) {
    log_debug("EVENT_EBPF_TRACEPOINT: Failed to get CPU registers for VCPU %u",
              vcpu_id);
    return;
  }

  if (strstr(func_name, "bpf_prog_attach")) {
    uint32_t prog_fd = (uint32_t)regs.x86.rdi;
    uint32_t attach_type = (uint32_t)regs.x86.rdx;

    log_debug("EVENT_EBPF_TRACEPOINT: Program FD: %u, Attach Type: %u", prog_fd,
              attach_type);

    if (attach_type == 1 || attach_type == 2) {
      log_warn(
          "EVENT_EBPF_TRACEPOINT: Network traffic interception capability "
          "detected");
    } else if (attach_type >= 14 && attach_type <= 17) {
      log_warn(
          "EVENT_EBPF_TRACEPOINT: Container/cgroup manipulation capability "
          "detected");
    }

    if (attach_type_out) {
      *attach_type_out = attach_type;
    }

  } else if (strstr(func_name, "bpf_raw_tracepoint")) {
    addr_t name_ptr = regs.x86.rdi;
    if (name_ptr) {
      char* tp_name = vmi_read_str_va(vmi, name_ptr, 0);
      if (tp_name) {
        log_debug("EVENT_EBPF_TRACEPOINT: Tracepoint: %s", tp_name);

        if (strstr(tp_name, "sys_enter") || strstr(tp_name, "sys_exit")) {
          log_warn(
              "EVENT_EBPF_TRACEPOINT: System call tracing capability detected");
        } else if (strstr(tp_name, "sched_process")) {
          log_warn(
              "EVENT_EBPF_TRACEPOINT: Process monitoring capability detected");
        } else if (strstr(tp_name, "net_dev") || strstr(tp_name, "sock")) {
          log_warn(
              "EVENT_EBPF_TRACEPOINT: Network monitoring capability detected");
        }

        if (tracepoint_name_out) {
          *tracepoint_name_out = g_strdup(tp_name);
        }
        g_free(tp_name);
      }
    }
  } else if (strstr(func_name, "tracepoint_probe_register")) {
    addr_t tp_ptr = regs.x86.rdi;  // struct tracepoint *tp
    if (!tp_ptr)
      return;

    // Read tracepoint name using proper offset from offsets.h
    addr_t name_ptr = 0;
    if (vmi_read_addr_va(vmi, tp_ptr + LINUX_TRACEPOINT_NAME_OFFSET, 0,
                         &name_ptr) == VMI_SUCCESS &&
        name_ptr) {
      char* tp_name = vmi_read_str_va(vmi, name_ptr, 0);
      if (tp_name) {
        log_info("EVENT_EBPF_TRACEPOINT: Tracepoint registration: %s", tp_name);
        if (tracepoint_name_out)
          *tracepoint_name_out = g_strdup(tp_name);
        g_free(tp_name);
      } else {
        log_debug(
            "EVENT_EBPF_TRACEPOINT: tracepoint->name unreadable (ptr=0x%" PRIx64
            ")",
            name_ptr);
      }
    } else {
      log_debug(
          "EVENT_EBPF_TRACEPOINT: Could not read tracepoint->name from "
          "0x%" PRIx64,
          tp_ptr);
    }
  }
}

/**
 * @brief Single-step callback for eBPF tracepoint monitoring.
 * 
 * Re-arms the breakpoint after the original instruction has executed.
 * Follows the established single-step pattern used by io_uring and netfilter.
 * 
 * @param vmi VMI instance
 * @param event Single-step event
 * @return event_response_t VMI_EVENT_RESPONSE_NONE
 */
static event_response_t event_ebpf_tracepoint_ss_callback(vmi_instance_t vmi,
                                                          vmi_event_t* event) {

  ebpf_tracepoint_ctx_t* ctx = (ebpf_tracepoint_ctx_t*)event->data;
  if (!ctx) {
    log_error("EVENT_EBPF_TRACEPOINT: NULL context in SS handler.");
    return VMI_EVENT_INVALID;
  }

  // Re-arm the breakpoint by writing INT3 back
  uint8_t int3 = 0xCC;
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &int3) != VMI_SUCCESS) {
    log_warn("EVENT_EBPF_TRACEPOINT: Failed to re-arm breakpoint at 0x%" PRIx64,
             ctx->kaddr);
  }

  // Disable single-step on this VCPU
  if (vmi_toggle_single_step_vcpu(vmi, event, event->vcpu_id, false) !=
      VMI_SUCCESS) {
    log_warn("EVENT_EBPF_TRACEPOINT: Failed to disable single-step on VCPU %u",
             event->vcpu_id);
  }

  // Note: We don't clear the single-step event here as it's automatically
  // cleaned up by LibVMI when the event completes

  log_debug("EVENT_EBPF_TRACEPOINT: Breakpoint re-armed on vCPU %u",
            event->vcpu_id);

  log_vcpu_state(vmi, event->vcpu_id, ctx->kaddr, "SS exit");
  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t event_ebpf_tracepoint_callback(vmi_instance_t vmi,
                                                vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_interrupt(
        "ebpf_tracepoint", INTERRUPT_EBPF_TRACEPOINT, INVALID_ARGUMENTS,
        "Invalid arguments to eBPF tracepoint callback.");
  }

  ebpf_tracepoint_ctx_t* ctx = (ebpf_tracepoint_ctx_t*)event->data;
  if (!ctx) {
    return log_error_and_queue_response_interrupt(
        "ebpf_tracepoint", INTERRUPT_EBPF_TRACEPOINT, INVALID_ARGUMENTS,
        "NULL context in INT3 handler.");
  }

  if (ctx->kaddr == 0) {
    return log_error_and_queue_response_interrupt(
        "ebpf_tracepoint", INTERRUPT_EBPF_TRACEPOINT, INVALID_ARGUMENTS,
        "Invalid kaddr in context.");
  }

  event->interrupt_event.reinject = 0;
  event->interrupt_event.insn_length = 0;

  uint32_t vcpu_id = event->vcpu_id;
  uint64_t rip = 0, cr3 = 0, rsp = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "ebpf_tracepoint", INTERRUPT_EBPF_TRACEPOINT, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "ebpf_tracepoint", INTERRUPT_EBPF_TRACEPOINT, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "ebpf_tracepoint", INTERRUPT_EBPF_TRACEPOINT, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
  }

  vmi_pid_t pid = 0;
  if (vmi_dtb_to_pid(vmi, event->x86_regs->cr3, &pid) != VMI_SUCCESS) {
    log_debug(
        "EVENT_EBPF_TRACEPOINT: Could not determine PID for CR3 0x%" PRIx64,
        event->x86_regs->cr3);
    pid = 0;
  }

  log_warn(
      "EVENT_EBPF_TRACEPOINT: eBPF tracepoint program detected | "
      "VCPU: %u RIP: 0x%" PRIx64 " PID: %u Function: %s Address: 0x%" PRIx64,
      vcpu_id, (uint64_t)rip, pid, ctx->symname ? ctx->symname : "unknown",
      ctx->kaddr);

  uint32_t attach_type = 0;
  char* tracepoint_name = NULL;
  const char* program_type = "unknown";

  if (ctx->symname && strstr(ctx->symname, "bpf_")) {
    log_debug("EVENT_EBPF_TRACEPOINT: Type - eBPF program attachment");
    program_type = "bpf_prog";
    extract_ebpf_tracepoint_info(vmi, vcpu_id, ctx->symname, &attach_type,
                                 &tracepoint_name);
  } else if (ctx->symname && strstr(ctx->symname, "tracepoint")) {
    log_debug("EVENT_EBPF_TRACEPOINT: Type - Tracepoint probe registration");
    program_type = "tracepoint";
    extract_ebpf_tracepoint_info(vmi, vcpu_id, ctx->symname, &attach_type,
                                 &tracepoint_name);
  } else if (ctx->symname && strstr(ctx->symname, "fmod_ret")) {
    log_debug("EVENT_EBPF_TRACEPOINT: Type - fmod_ret program");
    program_type = "fmod_ret";
  }

  ebpf_tracepoint_data_t* ebpf_data = ebpf_tracepoint_data_new(
      vcpu_id, rip, rsp, cr3, pid, ctx->kaddr, ctx->symname, program_type,
      attach_type, tracepoint_name);

  if (tracepoint_name)
    g_free(tracepoint_name);

  if (!ebpf_data) {
    return log_error_and_queue_response_interrupt(
        "ebpf_tracepoint", INTERRUPT_EBPF_TRACEPOINT, MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for eBPF tracepoint data.");
  }

  // Restore original byte
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &ctx->orig) != VMI_SUCCESS) {
    log_error(
        "EVENT_EBPF_TRACEPOINT: Failed to restore original byte at 0x%" PRIx64,
        ctx->kaddr);
    ebpf_tracepoint_data_free(ebpf_data);
    return VMI_EVENT_INVALID;
  }

  memset(&ctx->ss_evt, 0, sizeof(ctx->ss_evt));
  ctx->ss_evt.version = VMI_EVENTS_VERSION;
  ctx->ss_evt.type = VMI_EVENT_SINGLESTEP;
  ctx->ss_evt.callback = event_ebpf_tracepoint_ss_callback;
  ctx->ss_evt.data = ctx;
  ctx->ss_evt.ss_event.enable = 1;

  if (vmi_register_event(vmi, &ctx->ss_evt) != VMI_SUCCESS) {
    log_warn(
        "EVENT_EBPF_TRACEPOINT: Failed to register SINGLESTEP event. "
        "Breakpoint will not be re-armed.");
    return log_success_and_queue_response_interrupt(
        "ebpf_tracepoint", INTERRUPT_EBPF_TRACEPOINT, (void*)ebpf_data,
        (void (*)(void*))ebpf_tracepoint_data_free);
  }

  if (vmi_toggle_single_step_vcpu(vmi, &ctx->ss_evt, vcpu_id, true) !=
      VMI_SUCCESS) {
    log_warn(
        "EVENT_EBPF_TRACEPOINT: Failed to enable single-step on vCPU %u. "
        "Breakpoint will not be re-armed.",
        vcpu_id);
  }

  log_debug("EVENT_EBPF_TRACEPOINT: Single-step enabled on vCPU %u.", vcpu_id);

  log_vcpu_state(vmi, vcpu_id, ctx->kaddr, "CB exit");

  return log_success_and_queue_response_interrupt(
      "ebpf_tracepoint", INTERRUPT_EBPF_TRACEPOINT, (void*)ebpf_data,
      (void (*)(void*))ebpf_tracepoint_data_free);
}
