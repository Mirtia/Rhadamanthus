#include "event_callbacks/cr0_write.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/responses/cr0_write_response.h"
#include "json_serializer.h"
#include "utils.h"

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

event_response_t event_cr0_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_event(
        "cr0_write", EVENT_CR0_WRITE, INVALID_ARGUMENTS,
        "Invalid arguments to CR0 write callback.");
  }

  cr0_write_data_t* response = g_malloc0(sizeof(cr0_write_data_t));
  if (!response) {
    return log_error_and_queue_response_event(
        "cr0_write", EVENT_CR0_WRITE, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  uint64_t cr0_value = event->reg_event.value;
  uint32_t vcpu_id = event->vcpu_id;

  uint64_t rip = 0, cr3 = 0, rsp = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "cr0_write", EVENT_CR0_WRITE, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "cr0_write", EVENT_CR0_WRITE, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "cr0_write", EVENT_CR0_WRITE, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
  }
  cr0_write_data_t* cr0_data =
      cr0_write_data_new(vcpu_id, rip, rsp, cr3, cr0_value);
  if (!cr0_data) {
    return log_error_and_queue_response_event(
        "cr0_write", EVENT_CR0_WRITE, MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for CR0 write data.");
  }
  const char* protection_enabled = (cr0_value & CR0_PE) ? "ON" : "OFF";
  const char* paging_enabled = (cr0_value & CR0_PG) ? "ON" : "OFF";
  const char* write_protect = (cr0_value & CR0_WP) ? "ON" : "OFF";
  const char* cache_disabled = (cr0_value & CR0_CD) ? "ON" : "OFF";
  const char* alignment_mask = (cr0_value & CR0_AM) ? "ON" : "OFF";

  log_debug("CR0 WRITE Event: PE=%s PG=%s WP=%s CD=%s AM=%s",
            protection_enabled, paging_enabled, write_protect, cache_disabled,
            alignment_mask);

  // Rootkits often clear write protection bit to modify read-only kernel structures (e.g. syscall table).
  // TODO: Is there a scenario where a malicious actor modifies the CR0_CD?
  if (!(cr0_value & CR0_WP)) {
    log_warn(
        "Write protection disabled (WP=0). Possible kernel modification of "
        "read-only structures.");
  }

  return log_success_and_queue_response_event(
      "cr0_write", EVENT_CR0_WRITE, (void*)cr0_data,
      (void (*)(void*))cr0_write_data_free);
}
