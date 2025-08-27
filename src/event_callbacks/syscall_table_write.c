#include "event_callbacks/syscall_table_write.h"
#include <inttypes.h>
#include <log.h>

event_response_t event_syscall_table_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  if (!vmi || !event) {
    log_error("Invalid arguments to syscall table write callback.");
    return VMI_EVENT_RESPONSE_NONE;
  }

  uint32_t vcpu_id = event->vcpu_id;
  addr_t write_gla = event->mem_event.gla;
  addr_t write_gpa = event->mem_event.gfn << 12;
  addr_t rip = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    log_error("Failed to get RIP for VCPU %u", vcpu_id);
  }

  log_info("SYSCALL TABLE WRITE Event: VCPU: %u RIP: 0x%" PRIx64
           " GLA: 0x%" PRIx64 " GPA: 0x%" PRIx64,
           vcpu_id, rip, write_gla, write_gpa);

  return VMI_EVENT_RESPONSE_NONE;
}
