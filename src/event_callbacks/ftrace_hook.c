#include "event_callbacks/ftrace_hook.h"
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <log.h>
#include "event_callbacks/responses/ftrace_hook_response.h"
#include "json_serializer.h"
#include "offsets.h"
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

  // Read the current value at the modified address to see what was written
  uint64_t current_value = 0;
  if (vmi_read_va(vmi, gla, 0, sizeof(uint64_t), &current_value, NULL) !=
      VMI_SUCCESS) {
    log_warn(
        "EVENT_FTRACE_HOOK: Failed to read current value at GLA 0x%" PRIx64,
        gla);
    current_value = 0;
  }

  // Try to read the original value (this might not always work depending on timing)
  uint64_t original_value = 0;

  // Get function name from RIP
  access_context_t access_ctx = {.version = ACCESS_CONTEXT_VERSION,
                                 .translate_mechanism = VMI_TM_NONE,
                                 .addr = 0,
                                 .dtb = cr3};
  const char* symname = vmi_translate_v2ksym(vmi, &access_ctx, rip);

  // Don't try to resolve function names - let the state callback handle that
  const char* target_function = NULL;

  const char* location = "KERNEL";
  if (rip >= LINUX_MODULE_START && rip <= LINUX_MODULE_END) {
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

  // Function resolution is handled by the state callback

  // Determine what type of value we're dealing with
  const char* value_type = "unknown";
  if (current_value == 0) {
    value_type = "NULL";
  } else if (current_value < 0x1000) {
    value_type = "flag/offset";
  } else if (current_value >= 0xffffffff80000000ULL &&
             current_value <= 0xffffffffffffffffULL) {
    value_type = "kernel_pointer";
  } else if (current_value >= 0xffff800000000000ULL) {
    value_type = "structure_pointer";
  } else {
    value_type = "other";
  }

  log_warn(
      "EVENT_FTRACE_HOOK: Modification details | "
      "Original: 0x%" PRIx64 " -> New: 0x%" PRIx64
      " | "
      "Value type: %s | "
      "Modification type: %s",
      original_value, current_value, value_type,
      current_value == 0    ? "CLEARING/REMOVING"
      : original_value == 0 ? "ADDING/INSERTING"
                            : "REPLACING");

  // Determine modification type
  const char* modification_type = NULL;
  if (current_value == 0) {
    modification_type = "REMOVING";
  } else if (original_value == 0) {
    modification_type = "ADDING";
  } else {
    modification_type = "REPLACING";
  }

  ftrace_hook_data_t* ftrace_data = ftrace_hook_data_new(
      vcpu_id, rip, rsp, cr3, rflags, gla, gpa, symname, original_value,
      current_value, value_type, modification_type);
  if (!ftrace_data) {
    return log_error_and_queue_response_event(
        "ftrace_hook", EVENT_FTRACE_HOOK, MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for ftrace hook data.");
  }

  // How to properly clear and register events!!!!!! ૮(˶╥︿╥)ა
  // https://github.com/libvmi/libvmi/blob/master/examples/event-example.c
  vmi_clear_event(vmi, event, NULL);
  vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

  return log_success_and_queue_response_event(
      "ftrace_hook", EVENT_FTRACE_HOOK, (void*)ftrace_data,
      (void (*)(void*))ftrace_hook_data_free);
}