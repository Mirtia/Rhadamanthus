#include "event_callbacks/page_table_modification.h"
#include <log.h>

event_response_t event_page_table_modification_callback(vmi_instance_t vmi,
                                                         vmi_event_t* event) {
  (void)vmi;
  (void)event;
  log_info("Page table modification event triggered.");
  return VMI_EVENT_RESPONSE_NONE;
}