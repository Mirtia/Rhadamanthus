#include "event_callbacks/kallsyms_table_write.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/responses/kallsyms_table_write_response.h"
#include "json_serializer.h"
#include "utils.h"

event_response_t event_kallsyms_write_callback(vmi_instance_t vmi,
                                               vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_event(
        "kallsyms_table_write", EVENT_KALLSYMS_TABLE_WRITE, INVALID_ARGUMENTS,
        "Invalid arguments to kallsyms table write callback.");
  }

  uint32_t vcpu_id = event->vcpu_id;
  addr_t gla = event->mem_event.gla;
  addr_t gpa = (event->mem_event.gfn << 12) | event->mem_event.offset;

  uint64_t rip = 0, cr3 = 0, rsp = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "kallsyms_table_write", EVENT_KALLSYMS_TABLE_WRITE, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "kallsyms_table_write", EVENT_KALLSYMS_TABLE_WRITE, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "kallsyms_table_write", EVENT_KALLSYMS_TABLE_WRITE, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
  }

  kallsyms_table_write_data_t* kallsyms_data =
      kallsyms_table_write_data_new(vcpu_id, rip, rsp, cr3, gla, gpa);
  if (!kallsyms_data) {
    return log_error_and_queue_response_event(
        "kallsyms_table_write", EVENT_KALLSYMS_TABLE_WRITE,
        MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for kallsyms table write data.");
  }

  log_warn("EVENT_KALLSYMS_WRITE: VCPU: %u GLA: 0x%" PRIx64 " GPA: 0x%" PRIx64,
           vcpu_id, gla, gpa);

  return log_success_and_queue_response_event(
      "kallsyms_table_write", EVENT_KALLSYMS_TABLE_WRITE, (void*)kallsyms_data,
      (void (*)(void*))kallsyms_table_write_data_free);
}