#include "event_callbacks/ebpf_map_update.h"
#include <log.h>

event_response_t event_ebpf_map_update_callback(vmi_instance_t vmi,
                                                vmi_event_t* event) {
  (void)vmi;
  (void)event;
  log_info("eBPF map update event triggered.");
  return VMI_EVENT_RESPONSE_NONE;
}
