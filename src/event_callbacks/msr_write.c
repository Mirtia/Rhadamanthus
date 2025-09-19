#include "event_callbacks/msr_write.h"
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include <time.h>
#include "event_callbacks/responses/msr_write_response.h"
#include "json_serializer.h"
#include "utils.h"

event_response_t event_msr_write_callback(vmi_instance_t vmi,
                                          vmi_event_t* event) {
  // Preconditions
  if (!vmi || !event) {
    return log_error_and_queue_response_event(
        "msr_write", EVENT_MSR_WRITE, INVALID_ARGUMENTS,
        "Invalid arguments to MSR write callback.");
  }

  uint32_t vcpu_id = event->vcpu_id;
  uint64_t msr_value = event->reg_event.value;
  uint64_t msr_index = event->reg_event.reg;

  uint64_t rip = 0, cr3 = 0, rsp = 0;

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "msr_write", EVENT_MSR_WRITE, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "msr_write", EVENT_MSR_WRITE, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_event(
        "msr_write", EVENT_MSR_WRITE, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
  }

  msr_write_data_t* msr_data =
      msr_write_data_new(vcpu_id, rip, rsp, cr3, msr_index, msr_value);
  if (!msr_data) {
    return log_error_and_queue_response_event(
        "msr_write", EVENT_MSR_WRITE, MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for MSR write data.");
  }

  // Enhanced logging with comprehensive context
  log_warn("=== MSR WRITE DETECTION ===");
  log_warn("Timestamp: %ld", time(NULL));
  log_warn("Event: Model Specific Register write detected");
  log_warn("Context: vCPU=%u RIP=0x%" PRIx64 " RSP=0x%" PRIx64
           " CR3=0x%" PRIx64,
           vcpu_id, rip, rsp, cr3);
  log_warn("MSR Details: Index=0x%" PRIx64 " Value=0x%" PRIx64, msr_index,
           msr_value);

  // Check for security-relevant MSR writes
  const char* msr_name = msr_get_name(msr_index);
  if (msr_needs_further_investigation(msr_index)) {
    log_warn("Suspicious MSR write detected: %s (0x%" PRIx64 ") = 0x%" PRIx64,
             msr_name ? msr_name : "unknown", msr_index, msr_value);
  }

  return log_success_and_queue_response_event(
      "msr_write", EVENT_MSR_WRITE, (void*)msr_data,
      (void (*)(void*))msr_write_data_free);
}