#include "event_callbacks/syscall_table_write.h"
#include <log.h>

event_response_t event_syscall_table_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  (void)vmi;
  (void)event;
  log_info("Syscall table write event triggered.");
  return VMI_EVENT_RESPONSE_NONE;
}
