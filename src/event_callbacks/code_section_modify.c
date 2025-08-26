#include "event_callbacks/code_section_modify.h"

event_response_t event_code_section_modify_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  (void)vmi;
  (void)event;
  return VMI_EVENT_RESPONSE_NONE;
}