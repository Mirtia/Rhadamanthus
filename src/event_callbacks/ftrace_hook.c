#include "event_callbacks/ftrace_hook.h"
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/responses/ftrace_hook_response.h"
#include "json_serializer.h"
#include "utils.h"

event_response_t event_ftrace_hook_callback(vmi_instance_t vmi,
                                            vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_event(
        "ftrace_hook", EVENT_FTRACE_HOOK, INVALID_ARGUMENTS,
        "Invalid arguments to ftrace hook callback.");
  }

  uint32_t vcpu_id = event->vcpu_id;
  uint64_t rip = 0, cr3 = 0, rsp = 0, rflags = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "ftrace_hook", EVENT_FTRACE_HOOK, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "ftrace_hook", EVENT_FTRACE_HOOK, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "ftrace_hook", EVENT_FTRACE_HOOK, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
  }

  if (vmi_get_vcpureg(vmi, &rflags, RFLAGS, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "ftrace_hook", EVENT_FTRACE_HOOK, VMI_OP_FAILURE,
        "Failed to get RFLAGS register value.");
  }

  uint64_t gla = event->mem_event.gla;
  uint64_t gpa = (event->mem_event.gfn << 12) | event->mem_event.offset;

  // Get function name from RIP
  const char* symname = vmi_translate_v2ksym(vmi, NULL, rip);

  // Determine if this is in kernel module space
  const char* location = "KERNEL";
  if (rip >= 0xffffffffc0000000 && rip <= 0xffffffffc0ffffff) {
    location = "MODULE";
  }

  // Analyze execution context
  const char* context = "UNKNOWN";
  if (rflags & 0x200) {  // IF (Interrupt Flag)
    context = "INTERRUPTS_ENABLED";
  } else {
    context = "INTERRUPTS_DISABLED";
  }

  log_warn(
      "EVENT_FTRACE_HOOK: ftrace_ops_list modification detected | "
      "VCPU: %u RIP: 0x%" PRIx64 " RSP: 0x%" PRIx64 " CR3: 0x%" PRIx64
      " | "
      "GLA: 0x%" PRIx64 " GPA: 0x%" PRIx64
      " | "
      "Function: %s Location: %s Context: %s",
      vcpu_id, rip, rsp, cr3, gla, gpa, symname ? symname : "unknown", location,
      context);

  ftrace_hook_data_t* ftrace_data =
      ftrace_hook_data_new(vcpu_id, rip, rsp, cr3, rflags, gla, gpa, symname);
  if (!ftrace_data) {
    return log_error_and_queue_response_event(
        "ftrace_hook", EVENT_FTRACE_HOOK, MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for ftrace hook data.");
  }

  return log_success_and_queue_response_event(
      "ftrace_hook", EVENT_FTRACE_HOOK, (void*)ftrace_data,
      (void (*)(void*))ftrace_hook_data_free);
}