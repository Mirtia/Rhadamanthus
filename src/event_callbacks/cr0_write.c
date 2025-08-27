#include "event_callbacks/cr0_write.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>

/* CR0 Constants */
#define CR0_PE (1UL << 0)  /* Protection Enable */
#define CR0_WP (1UL << 16) /* Write Protect */
#define CR0_AM (1UL << 18) /* Alignment Mask */
#define CR0_CD (1UL << 30) /* Cache Disable */
#define CR0_PG (1UL << 31) /* Paging Enable */

event_response_t event_cr0_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event) {

  if (!vmi || !event) {
    log_error("Invalid arguments to CR0 write callback.");
    return VMI_EVENT_INVALID;
  }

  uint64_t cr0_value = event->reg_event.value;
  uint32_t vcpu_id = event->vcpu_id;

  // Get additional register values
  uint64_t rip = 0, cr3 = 0, rsp = 0;
  vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id);
  vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id);
  vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id);

  // Decode CR0 bits for analysis
  const char* protection_enabled = (cr0_value & CR0_PE) ? "ON" : "OFF";
  const char* paging_enabled = (cr0_value & CR0_PG) ? "ON" : "OFF";
  const char* write_protect = (cr0_value & CR0_WP) ? "ON" : "OFF";
  const char* cache_disabled = (cr0_value & CR0_CD) ? "ON" : "OFF";
  const char* alignment_mask = (cr0_value & CR0_AM) ? "ON" : "OFF";

  vmi_pid_t pid = 0;
  // Note: Use of vmi_dtb_to_pid is discouraged in events.
  // Pid does not make sense on this context, module is the one modifying the WP bit. (See Notes)
  log_info("CR0 WRITE Event: PE=%s PG=%s WP=%s CD=%s AM=%s PID=unknown",
           protection_enabled, paging_enabled, write_protect, cache_disabled,
           alignment_mask);

  // TODO: Investigate
  if (!(cr0_value & CR0_PE)) {
    log_debug("Protection mode disabled.");
  }

  if (!(cr0_value & CR0_PG)) {
    log_debug("Paging disabled.");
  }
  // TODO: Find PoC for this case.(??)
  if (cr0_value & CR0_CD) {
    log_debug("CPU cache disabled.");
  }

  return VMI_EVENT_RESPONSE_NONE;
}