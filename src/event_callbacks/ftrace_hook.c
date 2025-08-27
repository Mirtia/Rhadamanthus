#include "event_callbacks/ftrace_hook.h"
#include <log.h>

event_response_t event_ftrace_hook_callback(vmi_instance_t vmi,
                                            vmi_event_t* event) {
  (void)vmi;
  (void)event;
  log_info("Ftrace hook event triggered.");
  return VMI_EVENT_RESPONSE_NONE;
}