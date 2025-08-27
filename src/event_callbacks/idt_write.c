#include "event_callbacks/idt_write.h"
#include <log.h>

event_response_t event_idt_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event) {
  (void)vmi;
  (void)event;
  log_info("IDT write event triggered.");
  return VMI_EVENT_RESPONSE_NONE;
}