#include "event_callbacks/netfilter_hook_write.h"
#include <log.h>

event_response_t event_netfilter_hook_write_callback(vmi_instance_t vmi,
                                                     vmi_event_t* event) {
  (void)vmi;
  (void)event;
  log_info("Netfilter hook write event triggered.");
  return VMI_EVENT_RESPONSE_NONE;
}
