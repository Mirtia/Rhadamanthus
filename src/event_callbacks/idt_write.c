#include "event_callbacks/idt_write.h"
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <log.h>
#include "event_callbacks/responses/idt_write_response.h"
#include "json_serializer.h"
#include "utils.h"

event_response_t event_idt_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_event(
        "idt_write", EVENT_IDT_WRITE, INVALID_ARGUMENTS,
        "Invalid arguments to IDT write callback.");
  }

  uint32_t vcpu_id = event->vcpu_id;
  addr_t write_gla = event->mem_event.gla;
  addr_t write_gpa = (event->mem_event.gfn << 12) | event->mem_event.offset;

  uint64_t rip = 0, cr3 = 0, rsp = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "idt_write", EVENT_IDT_WRITE, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "idt_write", EVENT_IDT_WRITE, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "idt_write", EVENT_IDT_WRITE, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
  }

  idt_write_data_t* idt_data =
      idt_write_data_new(vcpu_id, rip, rsp, cr3, write_gla, write_gpa);
  if (!idt_data) {
    return log_error_and_queue_response_event(
        "idt_write", EVENT_IDT_WRITE, MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for IDT write data.");
  }

  log_warn("EVENT_IDT_WRITE: VCPU: %u RIP: 0x%" PRIx64 " GLA: 0x%" PRIx64
           " GPA: 0x%" PRIx64,
           vcpu_id, rip, write_gla, write_gpa);

  // IDT modifications are highly suspicious - classic rootkit technique for system call hooking
  log_warn("CRITICAL: IDT (Interrupt Descriptor Table) modification detected");
  log_warn(
      "Potential rootkit activity: IDT hooking for system call/interrupt "
      "interception");

  return log_success_and_queue_response_event(
      "idt_write", EVENT_IDT_WRITE, (void*)idt_data,
      (void (*)(void*))idt_write_data_free);
}