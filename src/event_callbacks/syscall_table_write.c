#include "event_callbacks/syscall_table_write.h"
#include <inttypes.h>
#include <log.h>

event_response_t event_syscall_table_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    log_error(
        "SYSCALL_TABLE_WRITE: Invalid arguments to syscall table write "
        "callback.");
    return VMI_EVENT_RESPONSE_NONE;
  }

  log_info("Syscall table write event triggered.");

  uint32_t vcpu_id = event->vcpu_id;
  addr_t write_gla = event->mem_event.gla;
  addr_t write_gpa = (event->mem_event.gfn << 12) | event->mem_event.offset;

  addr_t rip = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    log_error("SYSCALL_TABLE_WRITE: Failed to get RIP for VCPU %u", vcpu_id);
    return VMI_FAILURE;
  }

  log_warn("SYSCALL_TABLE_WRITE Event: VCPU: %u RIP: 0x%" PRIx64
           " GLA: 0x%" PRIx64 " GPA: 0x%" PRIx64,
           vcpu_id, rip, write_gla, write_gpa);

  return VMI_EVENT_RESPONSE_NONE;
}
