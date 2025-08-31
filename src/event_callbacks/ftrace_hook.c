#include "event_callbacks/ftrace_hook.h"
#include <inttypes.h>
#include <log.h>

event_response_t event_ftrace_hook_callback(vmi_instance_t vmi,
                                            vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    log_error("EVENT_FTRACE_HOOK: Invalid arguments to ftrace hook callback.");
    return VMI_EVENT_INVALID;
  }

  uint32_t vcpu_id = event->vcpu_id;
  addr_t rip = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    log_warn("EVENT_FTRACE_HOOK: Failed to get RIP for VCPU %u", vcpu_id);
  }

  uint64_t gla = event->mem_event.gla;
  uint64_t gpa = (event->mem_event.gfn << 12) | event->mem_event.offset;

  vmi_mem_access_t in_access = event->mem_event.in_access;
  vmi_mem_access_t out_access = event->mem_event.out_access;

  log_warn(
      "EVENT_FTRACE_HOOK: Write to ftrace_ops_list detected | "
      "VCPU: %u RIP: 0x%" PRIx64 " GLA: 0x%" PRIx64 " GPA: 0x%" PRIx64
      " IN_ACCESS: 0x%x OUT_ACCESS: 0x%x",
      vcpu_id, (uint64_t)rip, gla, gpa, (unsigned)in_access,
      (unsigned)out_access);

  return VMI_EVENT_RESPONSE_NONE;
}