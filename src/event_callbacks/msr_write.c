#include "event_callbacks/msr_write.h"
#include <inttypes.h>
#include <log.h>

event_response_t event_msr_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event) {
  if (!vmi || !event) {
    log_error("EVENT_MSR_WRITE: Invalid arguments to MSR write callback.");
    return VMI_EVENT_INVALID;
  }

  uint32_t vcpu_id = event->vcpu_id;
  addr_t rip = 0;
  uint64_t msr_value = event->reg_event.value;
  uint64_t msr_index = event->reg_event.reg;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    log_warn("EVENT_MSR_WRITE: Failed to get RIP for VCPU %u", vcpu_id);
  }

  log_warn("EVENT_MSR_WRITE: VCPU: %u RIP: 0x%" PRIx64 " MSR_INDEX: 0x%" PRIx64
           " VALUE: 0x%" PRIx64,
           vcpu_id, rip, msr_index, msr_value);

  return VMI_EVENT_RESPONSE_NONE;
}
