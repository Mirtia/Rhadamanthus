#include "event_callbacks/kallsyms_table_write.h"
#include <inttypes.h>
#include <log.h>

event_response_t event_kallsyms_table_write_callback(vmi_instance_t vmi,
                                                     vmi_event_t* event) {

  if (!vmi || !event) {
    log_error("Invalid arguments to kallsyms table write callback.");
    return VMI_EVENT_INVALID;
  }

  uint32_t vcpu_id = event->vcpu_id;
  addr_t gla = event->mem_event.gla;
  addr_t gpa = event->mem_event.gfn << 12;

  log_warn("KALLSYMS WRITE Event: VCPU: %u GLA: 0x%" PRIx64 " GPA: 0x%" PRIx64,
           vcpu_id, gla, gpa);

  log_info("Invoking kallsyms state check for deeper analysis...");

  return VMI_EVENT_RESPONSE_NONE;
}
