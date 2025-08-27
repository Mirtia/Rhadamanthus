#include "event_callbacks/io_uring_ring_write.h"
#include <log.h>

event_response_t event_io_uring_ring_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  (void)vmi;
  (void)event;
  log_info("io_uring ring write event triggered.");
  return VMI_EVENT_RESPONSE_NONE;
}
