#include "event_callbacks/syscall_table_write.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/responses/syscall_table_write_response.h"
#include "json_serializer.h"
#include "utils.h"

event_response_t event_syscall_table_write_callback(vmi_instance_t vmi,
                                                    vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_event(
        "syscall_table_write", EVENT_SYSCALL_TABLE_WRITE, INVALID_ARGUMENTS,
        "Invalid arguments to syscall table write callback.");
  }

  uint32_t vcpu_id = event->vcpu_id;
  addr_t write_gla = event->mem_event.gla;
  addr_t write_gpa = (event->mem_event.gfn << 12) | event->mem_event.offset;

  uint64_t rip = 0, cr3 = 0, rsp = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "syscall_table_write", EVENT_SYSCALL_TABLE_WRITE, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "syscall_table_write", EVENT_SYSCALL_TABLE_WRITE, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "syscall_table_write", EVENT_SYSCALL_TABLE_WRITE, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
  }

  syscall_table_write_data_t* syscall_data = syscall_table_write_data_new(
      vcpu_id, rip, rsp, cr3, write_gla, write_gpa);
  if (!syscall_data) {
    return log_error_and_queue_response_event(
        "syscall_table_write", EVENT_SYSCALL_TABLE_WRITE,
        MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for syscall table write data.");
  }

  log_warn("SYSCALL_TABLE_WRITE Event: VCPU: %u RIP: 0x%" PRIx64
           " GLA: 0x%" PRIx64 " GPA: 0x%" PRIx64,
           vcpu_id, rip, write_gla, write_gpa);

  log_warn(
      "SYSCALL_TABLE_WRITE Event: Suspicious activity detected. Syscall table "
      "modification at GPA: "
      "0x%" PRIx64,
      write_gpa);

  return log_success_and_queue_response_event(
      "syscall_table_write", EVENT_SYSCALL_TABLE_WRITE, (void*)syscall_data,
      (void (*)(void*))syscall_table_write_data_free);
}