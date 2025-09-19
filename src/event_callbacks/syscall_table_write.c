#include "event_callbacks/syscall_table_write.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include "event_callbacks/responses/syscall_table_write_response.h"
#include "json_serializer.h"
#include "utils.h"

/**
 * @brief Calculate syscall number from syscall table address
 * 
 * @param vmi VMI instance
 * @param write_gla Guest linear address of the write
 * @return Syscall number, or 0 if calculation fails
 */
static uint32_t calculate_syscall_number(vmi_instance_t vmi,
                                         uint64_t write_gla) {
  addr_t sys_call_table_addr = 0;

  // Get the address of sys_call_table
  if (vmi_translate_ksym2v(vmi, "sys_call_table", &sys_call_table_addr) !=
      VMI_SUCCESS) {
    log_debug("Failed to resolve sys_call_table symbol");
    return 0;
  }

  // Calculate the offset from the start of the syscall table
  uint64_t offset = write_gla - sys_call_table_addr;

  // Each syscall entry is 8 bytes (64-bit pointer)
  uint32_t syscall_number = (uint32_t)(offset / 8);

  log_debug("Syscall table calculation: table_addr=0x%" PRIx64
            " write_gla=0x%" PRIx64 " offset=%" PRIu64 " syscall_number=%u",
            sys_call_table_addr, write_gla, offset, syscall_number);

  return syscall_number;
}

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

  // Calculate which syscall is being modified
  uint32_t syscall_number = calculate_syscall_number(vmi, write_gla);
  char* syscall_name = resolve_syscall_name(syscall_number);

  syscall_table_write_data_t* syscall_data =
      syscall_table_write_data_new(vcpu_id, rip, rsp, cr3, write_gla, write_gpa,
                                   syscall_number, syscall_name);
  if (!syscall_data) {
    if (syscall_name)
      g_free(syscall_name);
    return log_error_and_queue_response_event(
        "syscall_table_write", EVENT_SYSCALL_TABLE_WRITE,
        MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for syscall table write data.");
  }

  log_warn("SYSCALL_TABLE_WRITE Event: VCPU: %u RIP: 0x%" PRIx64
           " GLA: 0x%" PRIx64 " GPA: 0x%" PRIx64 " Syscall: %u (%s)",
           vcpu_id, rip, write_gla, write_gpa, syscall_number,
           syscall_name ? syscall_name : "unknown");

  log_warn(
      "SYSCALL_TABLE_WRITE Event: Suspicious activity detected. Syscall table "
      "modification at GPA: 0x%" PRIx64 " affecting syscall %u (%s)",
      write_gpa, syscall_number, syscall_name ? syscall_name : "unknown");

  return log_success_and_queue_response_event(
      "syscall_table_write", EVENT_SYSCALL_TABLE_WRITE, (void*)syscall_data,
      (void (*)(void*))syscall_table_write_data_free);
}