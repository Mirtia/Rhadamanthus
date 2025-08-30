#include "state_callbacks/msr_registers.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include "utils.h"

/**
 * @brief Get the legitimate syscall entry point symbol
 *
 * @param vmi LibVMI instance
 * @param syscall_entry Output: legitimate syscall entry address
 * @return true on success, false on failure
 */
static bool get_legitimate_syscall_entry(vmi_instance_t vmi,
                                         addr_t* syscall_entry) {
  if (!syscall_entry) {
    return false;
  }

  // Try common syscall entry symbols (kernel version dependent)
  const char* syscall_symbols[] = {
      "entry_SYSCALL_64",  // Modern kernels
      "system_call",       // Older kernels (as mentioned in vvdveen's document)
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
  (void)context;

  log_info("Executing STATE_MSR_REGISTERS callback.");

  addr_t kernel_start = 0, kernel_end = 0;
  if (get_kernel_text_section_range(vmi, &kernel_start, &kernel_end) !=
      VMI_SUCCESS) {
    log_error(
        "STATE_MSR_REGISTERS: Failed to get kernel .text section boundaries.");
    return VMI_FAILURE;
  }

  log_info("STATE_MSR_REGISTERS: Kernel text range: [0x%" PRIx64 ", 0x%" PRIx64
           "]",
           (uint64_t)kernel_start, (uint64_t)kernel_end);

  // Get legitimate syscall entry point for comparison
  addr_t legitimate_syscall = 0;
  bool has_legitimate_ref =
      get_legitimate_syscall_entry(vmi, &legitimate_syscall);

  // Get number of vCPUs
  unsigned int num_vcpus = vmi_get_num_vcpus(vmi);
  if (num_vcpus == 0) {
    log_error(
        "STATE_MSR_REGISTERS: Failed to get number of vCPUs or no vCPUs "
        "available.");
    return VMI_FAILURE;
  }

  log_info("STATE_MSR_REGISTERS: Reading MSR_LSTAR state from %u vCPU(s).",
           num_vcpus);

  // Read and report MSR_LSTAR state on each vCPU
  for (unsigned int cpu = 0; cpu < num_vcpus; cpu++) {
    addr_t lstar_value = 0;

    if (!read_msr_lstar(vmi, cpu, &lstar_value)) {
      log_warn("STATE_MSR_REGISTERS: Failed to read MSR_LSTAR from vCPU %u.",
               cpu);
      continue;
    }

    log_info("STATE_MSR_REGISTERS: vCPU %u MSR_LSTAR: 0x%" PRIx64, cpu,
             (uint64_t)lstar_value);

    // Check if MSR_LSTAR points within kernel text bounds
    bool within_kernel_text =
        (lstar_value >= kernel_start && lstar_value <= kernel_end);

    if (!within_kernel_text) {
      log_info(
          "STATE_MSR_REGISTERS: vCPU %u MSR_LSTAR points outside kernel text "
          "section (0x%" PRIx64 " not in [0x%" PRIx64 ", 0x%" PRIx64 "])",
          cpu, (uint64_t)lstar_value, (uint64_t)kernel_start,
          (uint64_t)kernel_end);
    } else {
      log_info(
          "STATE_MSR_REGISTERS: vCPU %u MSR_LSTAR within kernel text bounds",
          cpu);
    }

    // Report if differs from expected syscall entry
    if (has_legitimate_ref && lstar_value != legitimate_syscall) {
      log_info(
          "STATE_MSR_REGISTERS: vCPU %u MSR_LSTAR differs from expected "
          "syscall entry (0x%" PRIx64 " vs 0x%" PRIx64 ")",
          cpu, (uint64_t)lstar_value, (uint64_t)legitimate_syscall);
    }
  }

  log_info("STATE_MSR_REGISTERS callback completed.");
  return VMI_SUCCESS;
}