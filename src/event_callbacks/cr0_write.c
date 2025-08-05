#include "event_callbacks/cr0_write.h"
#include <log.h>

event_response_t event_cr0_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event) {
  log_info("EVENT_CR0_WRITE triggered.");
  return VMI_SUCCESS;
}
