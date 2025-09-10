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
  addr_t rip = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "ftrace_hook", EVENT_FTRACE_HOOK, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  uint64_t gla = event->mem_event.gla;
  uint64_t gpa = (event->mem_event.gfn << 12) | event->mem_event.offset;

  vmi_mem_access_t in_access = event->mem_event.in_access;
  vmi_mem_access_t out_access = event->mem_event.out_access;

  ftrace_hook_data_t* ftrace_data =
      ftrace_hook_data_new(vcpu_id, rip, gla, gpa);
  if (!ftrace_data) {
    return log_error_and_queue_response_event(
        "ftrace_hook", EVENT_FTRACE_HOOK, MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for ftrace hook data.");
  }

  log_warn(
      "EVENT_FTRACE_HOOK: Write to ftrace_ops_list detected | "
      "VCPU: %u RIP: 0x%" PRIx64 " GLA: 0x%" PRIx64 " GPA: 0x%" PRIx64
      " IN_ACCESS: 0x%x OUT_ACCESS: 0x%x",
      vcpu_id, (uint64_t)rip, gla, gpa, (unsigned)in_access,
      (unsigned)out_access);

  return log_success_and_queue_response_event(
      "ftrace_hook", EVENT_FTRACE_HOOK, (void*)ftrace_data,
      (void (*)(void*))ftrace_hook_data_free);
}