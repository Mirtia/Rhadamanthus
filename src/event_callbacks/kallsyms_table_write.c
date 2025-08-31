#include "event_callbacks/kallsyms_table_write.h"
#include <inttypes.h>
#include <log.h>

event_response_t event_kallsyms_write_callback(vmi_instance_t vmi,
                                               vmi_event_t* event) {
  (void)vmi;
  // Preconditions
  if (!event) {
    log_error(
        "EVENT_KALLSYMS_WRITE: Invalid arguments to kallsyms table write "
        "callback.");
    return VMI_EVENT_INVALID;
  }

  uint32_t vcpu_id = event->vcpu_id;
  addr_t gla = event->mem_event.gla;
  addr_t gpa = (event->mem_event.gfn << 12) | event->mem_event.offset;

  log_warn("EVENT_KALLSYMS_WRITE: VCPU: %u GLA: 0x%" PRIx64 " GPA: 0x%" PRIx64,
           vcpu_id, gla, gpa);

  return VMI_EVENT_RESPONSE_NONE;
}
