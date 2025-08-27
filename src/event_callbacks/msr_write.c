#include "event_callbacks/msr_write.h"
#include <log.h>

event_response_t event_msr_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event) {
  (void)vmi;
  (void)event;
  log_info("MSR write event triggered.");
  return VMI_EVENT_RESPONSE_NONE;
}
