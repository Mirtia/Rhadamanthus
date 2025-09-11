#include "state_callbacks/msr_registers.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include "state_callbacks/responses/msr_registers_response.h"
#include "utils.h"

/**
 * @brief Get the legitimate syscall entry point symbol
 *
 * @param vmi LibVMI instance
 * @param syscall_entry legitimate syscall entry address
 * @return true on success, false on failure
 */
static bool get_legitimate_syscall_entry(vmi_instance_t vmi,
                                         addr_t* syscall_entry) {
  if (!syscall_entry) {
    return false;
  }

  // Try common syscall entry symbols.
  const char* syscall_symbols[] = {
      "entry_SYSCALL_64",  ///< Modern kernels
      "system_call",  ///< Older kernels (as mentioned in vvdveen's document)
      "entry_SYSCALL_64_after_hwframe", NULL};

  for (int i = 0; syscall_symbols[i] != NULL; i++) {
    if (vmi_translate_ksym2v(vmi, syscall_symbols[i], syscall_entry) ==
        VMI_SUCCESS) {
      log_debug("Found legitimate syscall entry: %s at 0x%" PRIx64,
                syscall_symbols[i], (uint64_t)*syscall_entry);
      return true;
    }
  }

  log_debug("Could not resolve any known syscall entry symbols.");
  return false;
}

/**
 * @brief Read MSR_LSTAR value from a specific vCPU
 *
 * @param vmi LibVMI instance
 * @param vcpu_id vCPU identifier
 * @param lstar_value Output: MSR_LSTAR value
 * @return true on success, false on failure
 */
static bool read_msr_lstar(vmi_instance_t vmi, unsigned int vcpu_id,
                           addr_t* lstar_value) {
  if (!lstar_value) {
    log_debug("Output pointer is NULL in read_msr_lstar.");
    return false;
  }

  if (vmi_get_vcpureg(vmi, lstar_value, MSR_LSTAR, vcpu_id) != VMI_SUCCESS) {
    log_debug("Failed to read MSR_LSTAR from vCPU %u.", vcpu_id);
    return false;
  }

  return true;
}

uint32_t state_msr_registers_callback(vmi_instance_t vmi, void* context) {
  // Preconditions
  if (!context || !vmi) {
    return log_error_and_queue_response_task(
        "msr_registers_state", STATE_MSR_REGISTERS, INVALID_ARGUMENTS,
        "STATE_MSR_REGISTERS: Invalid context or VMI instance");
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler->is_paused) {
    return log_error_and_queue_response_task(
        "msr_registers_state", STATE_MSR_REGISTERS, INVALID_ARGUMENTS,
        "STATE_MSR_REGISTERS: Callback requires a valid event handler context");
  }

  log_info("Executing STATE_MSR_REGISTERS callback.");

  // Create MSR registers state data structure
  msr_registers_state_data_t* msr_data = msr_registers_state_data_new();
  if (!msr_data) {
    return log_error_and_queue_response_task(
        "msr_registers_state", STATE_MSR_REGISTERS, MEMORY_ALLOCATION_FAILURE,
        "STATE_MSR_REGISTERS: Failed to allocate memory for MSR registers "
        "state data");
  }

  addr_t kernel_start = 0, kernel_end = 0;
  if (get_kernel_text_section_range(vmi, &kernel_start, &kernel_end) !=
      VMI_SUCCESS) {
    msr_registers_state_data_free(msr_data);
    return log_error_and_queue_response_task(
        "msr_registers_state", STATE_MSR_REGISTERS, VMI_OP_FAILURE,
        "STATE_MSR_REGISTERS: Failed to get kernel .text section boundaries");
  }

  // Set kernel range in data structure
  msr_registers_state_set_kernel_range(msr_data, (uint64_t)kernel_start,
                                       (uint64_t)kernel_end);

  log_info("STATE_MSR_REGISTERS: Kernel text range: [0x%" PRIx64 ", 0x%" PRIx64
           "]",
           (uint64_t)kernel_start, (uint64_t)kernel_end);

  addr_t legitimate_syscall = 0;
  bool has_legitimate_ref =
      get_legitimate_syscall_entry(vmi, &legitimate_syscall);

  // Set legitimate syscall entry information
  const char* symbol_name = "unknown";
  if (has_legitimate_ref) {
    // Try to determine which symbol was found
    const char* syscall_symbols[] = {"entry_SYSCALL_64", "system_call",
                                     "entry_SYSCALL_64_after_hwframe", NULL};

    for (int i = 0; syscall_symbols[i] != NULL; i++) {
      addr_t test_addr = 0;
      if (vmi_translate_ksym2v(vmi, syscall_symbols[i], &test_addr) ==
              VMI_SUCCESS &&
          test_addr == legitimate_syscall) {
        symbol_name = syscall_symbols[i];
        break;
      }
    }
  }

  msr_registers_state_set_legitimate_entry(
      msr_data, (uint64_t)legitimate_syscall, symbol_name, has_legitimate_ref);

  // Get number of vCPUs
  unsigned int num_vcpus = vmi_get_num_vcpus(vmi);
  if (num_vcpus == 0) {
    msr_registers_state_data_free(msr_data);
    return log_error_and_queue_response_task(
        "msr_registers_state", STATE_MSR_REGISTERS, VMI_OP_FAILURE,
        "STATE_MSR_REGISTERS: Failed to get number of vCPUs or no vCPUs "
        "available");
  }

  log_info("STATE_MSR_REGISTERS: Reading MSR_LSTAR state from %u vCPU(s).",
           num_vcpus);

  uint32_t suspicious_vcpus = 0;

  // Read and report MSR_LSTAR state on each vCPU
  for (unsigned int cpu = 0; cpu < num_vcpus; cpu++) {
    addr_t lstar_value = 0;

    if (!read_msr_lstar(vmi, cpu, &lstar_value)) {
      log_warn(
          "STATE_MSR_REGISTERS: Failed to read MSR_LSTAR from vCPU "
          "%u.",
          cpu);
      continue;
    }

    log_debug("STATE_MSR_REGISTERS: vCPU %u MSR_LSTAR: 0x%" PRIx64, cpu,
              (uint64_t)lstar_value);

    bool in_kernel_text = is_in_kernel_text(vmi, lstar_value);
    bool matches_legitimate =
        has_legitimate_ref && (lstar_value == legitimate_syscall);
    bool is_suspicious =
        !in_kernel_text || (has_legitimate_ref && !matches_legitimate);

    if (!in_kernel_text) {
      log_warn(
          "STATE_MSR_REGISTERS: vCPU %u MSR_LSTAR points outside "
          "kernel text "
          "section (0x%" PRIx64 " not in [0x%" PRIx64 ", 0x%" PRIx64 "])",
          cpu, (uint64_t)lstar_value, (uint64_t)kernel_start,
          (uint64_t)kernel_end);
    } else {
      log_debug(
          "STATE_MSR_REGISTERS: vCPU %u MSR_LSTAR within kernel text "
          "bounds",
          cpu);
    }

    if (has_legitimate_ref && lstar_value != legitimate_syscall) {
      log_warn(
          "STATE_MSR_REGISTERS: vCPU %u MSR_LSTAR differs from "
          "expected "
          "syscall entry (0x%" PRIx64 " vs 0x%" PRIx64 ")",
          cpu, (uint64_t)lstar_value, (uint64_t)legitimate_syscall);
    }

    // Add vCPU information to data structure
    msr_registers_state_add_vcpu(msr_data, cpu, (uint64_t)lstar_value,
                                 in_kernel_text, matches_legitimate,
                                 is_suspicious);

    if (is_suspicious) {
      suspicious_vcpus++;
    }
  }

  // Set summary information
  msr_registers_state_set_summary(msr_data, num_vcpus, suspicious_vcpus);

  if (suspicious_vcpus > 0) {
    log_warn("STATE_MSR_REGISTERS: Found %u suspicious vCPU(s).",
             suspicious_vcpus);
  } else {
    log_info("STATE_MSR_REGISTERS: No suspicious vCPUs detected");
  }

  int result = log_success_and_queue_response_task(
      "msr_registers_state", STATE_MSR_REGISTERS, msr_data,
      (void (*)(void*))msr_registers_state_data_free);

  log_info("STATE_MSR_REGISTERS callback completed.");
  return result;
}