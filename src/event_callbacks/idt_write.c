#include "event_callbacks/idt_write.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <log.h>

event_response_t event_idt_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event) {
  if (!vmi || !event) {
    log_error("Invalid arguments to IDT write callback.");
    return VMI_EVENT_INVALID;
  }

  uint32_t vcpu_id = event->vcpu_id;
  uint64_t rip = 0;
  addr_t write_gla = event->mem_event.gla;
  /**
 * Calculate the exact GPA.
 * GFN gives the 4 KiB page base (gfn << 12).
 * The page offset is preserved across translation, so use (gla & 0xFFF).
 * Combine both: GPA = (GFN << 12) | (GLA & 0xFFF).
 */
  addr_t write_gpa =
      (event->mem_event.gfn << 12) | (event->mem_event.gla & 0xFFF);

  vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id);

  log_warn("IDT WRITE Event: VCPU: %u RIP: 0x%" PRIx64 " GLA: 0x%" PRIx64
           " GPA: 0x%" PRIx64,
           vcpu_id, rip, write_gla, write_gpa);

  return VMI_EVENT_RESPONSE_NONE;
}
