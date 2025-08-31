#include "event_callbacks/cr0_write.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>

/*
 * CR0 control register semantics and attacker relevance. These definitions were taken from "Intel® 64 and IA-32 Architectures
 * Software Developer’s Manual" (https://cdrdv2.intel.com/v1/dl/getContent/671200).
 *
 * * CR0.PE (bit 0): Enables protected-mode operation. Clearing this bit switches to real mode. 
 *   This flag does not enable paging directly. It only enables segment-level protection. To enable paging,
 *   both the PE and PG flags must be set.
 *
 * * CR0.WP (bit 16): Write protection bit. When set, kernel-mode (ring 0) is prevented from writing to read-only pages.
 *   Clearing WP allows ring 0 to modify read-only pages, e.g., syscall table/IDT.
 *   Kernel rootkits (e.g., Diamorphine) commonly clear WP to modify read-only sections.
 *
 * * CR0.AM (bit 18): Enables alignment checks.
 * * CR0.CD (bit 30): Disables CPU caching.
 * * CR0.PG (bit 31): Enables paging. Both PE and PG flags must be set to enable paging.
 */
#define CR0_PE (1UL << 0)
#define CR0_WP (1UL << 16)
#define CR0_AM (1UL << 18)
#define CR0_CD (1UL << 30)
#define CR0_PG (1UL << 31)

event_response_t event_cr0_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event) {
  if (!vmi || !event) {
    log_error("Invalid arguments to CR0 write callback.");
    return VMI_EVENT_INVALID;
  }

  uint64_t cr0_value = event->reg_event.value;
  uint32_t vcpu_id = event->vcpu_id;

  uint64_t rip = 0, cr3 = 0, rsp = 0;
  vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id);
  vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id);
  vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id);

  const char* protection_enabled = (cr0_value & CR0_PE) ? "ON" : "OFF";
  const char* paging_enabled = (cr0_value & CR0_PG) ? "ON" : "OFF";
  const char* write_protect = (cr0_value & CR0_WP) ? "ON" : "OFF";
  const char* cache_disabled = (cr0_value & CR0_CD) ? "ON" : "OFF";
  const char* alignment_mask = (cr0_value & CR0_AM) ? "ON" : "OFF";

  log_info("CR0 WRITE Event: PE=%s PG=%s WP=%s CD=%s AM=%s", protection_enabled,
           paging_enabled, write_protect, cache_disabled, alignment_mask);

  // Rootkits often clear write protection bit to modify read-only kernel structures (e.g. syscall table).
  // TODO: Is there a scenario where a malicious actor modifies the CR0_CD?
  if (!(cr0_value & CR0_WP)) {
    log_warn(
        "Write protection disabled (WP=0)—possible kernel modification in "
        "progress.");
  }

  return VMI_EVENT_RESPONSE_NONE;
}
