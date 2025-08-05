#ifndef CR0_WRITE_H
#define CR0_WRITE_H

#include <libvmi/events.h>
#include <libvmi/libvmi.h>
#include <stdint.h>

event_response_t event_cr0_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event);

#endif  // CR0_WRITE_H