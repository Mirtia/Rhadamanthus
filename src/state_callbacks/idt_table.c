#include "state_callbacks/idt_table.h"

#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "event_handler.h"
#include "json_serializer.h"
#include "state_callbacks/responses/idt_table_response.h"
#include "utils.h"

/**
 * @brief Read a 64-bit handler address from an IA-32e (x86_64) 16-byte IDT gate.
 *
 * Layout: offset_low[0:1], selector[2:3], ist[4], type[5], offset_mid[6:7], offset_high[8:11], zero[12:15].
 *
 * @param vmi       LibVMI instance.
 * @param idt_base  Virtual address of IDT base.
 * @param vector    Interrupt vector (0..255).
 * @param out       Output: resolved handler address.
 * @return true on success; false on read failure.
 */
static bool read_idt_entry_addr_ia32e(vmi_instance_t vmi, addr_t idt_base,
                                      uint16_t vector, addr_t* out) {
  if (!out) {
    log_error("Output pointer is NULL in read_idt_entry_addr_ia32e.");
    return false;
  }

  uint16_t off_low = 0, off_mid = 0;
  uint32_t off_high = 0;

  if (vmi_read_16_va(vmi, idt_base + (addr_t)vector * 16 + 0, 0, &off_low) !=
      VMI_SUCCESS)
    return false;
  if (vmi_read_16_va(vmi, idt_base + (addr_t)vector * 16 + 6, 0, &off_mid) !=
      VMI_SUCCESS)
    return false;
  if (vmi_read_32_va(vmi, idt_base + (addr_t)vector * 16 + 8, 0, &off_high) !=
      VMI_SUCCESS)
    return false;

  *out = (((addr_t)off_high) << 32) | (((addr_t)off_mid) << 16) |
         ((addr_t)off_low);
  return true;
}

/**
 * @brief Read a 32-bit handler address from an IA-32 (x86) 8-byte IDT gate.
 *
 * Layout: offset_low[0:1], selector[2:3], count[4], type[5], offset_high[6:7].
 *
 * @param vmi       LibVMI instance.
 * @param idt_base  Virtual address of IDT base.
 * @param vector    Interrupt vector (0..255).
 * @param out       Output: resolved handler address.
 * @return true on success; false on read failure.
 */
static bool read_idt_entry_addr_ia32(vmi_instance_t vmi, addr_t idt_base,
                                     uint16_t vector, addr_t* out) {
  if (!out)
    return false;

  uint16_t off_low = 0, off_high = 0;

  if (vmi_read_16_va(vmi, idt_base + (addr_t)vector * 8 + 0, 0, &off_low) !=
      VMI_SUCCESS)
    return false;
  if (vmi_read_16_va(vmi, idt_base + (addr_t)vector * 8 + 6, 0, &off_high) !=
      VMI_SUCCESS)
    return false;

  *out = (((addr_t)off_high) << 16) | ((addr_t)off_low);
  return true;
}

/**
 * @brief Check IDT handlers for a specific vCPU
 *
 * @param vmi LibVMI instance
 * @param vcpu_id vCPU identifier
 * @param kernel_start_addr Start of kernel text section
 * @param kernel_end_addr End of kernel text section
 * @param vec_names Array of interrupt vector names
 * @param idt_data IDT state data to populate
 * @return Number of hooked handlers detected
 */
static int check_idt_for_vcpu(vmi_instance_t vmi,
                              //NOLINTNEXTLINE
                              unsigned int vcpu_id, addr_t kernel_start_addr,
                              addr_t kernel_end_addr, GPtrArray* vec_names,
                              idt_table_state_data_t* idt_data) {
  // Read IDTR base from specific vCPU
  addr_t idt_base = 0;
  if (vmi_get_vcpureg(vmi, &idt_base, IDTR_BASE, vcpu_id) != VMI_SUCCESS) {
    log_error("Failed to read IDTR base from vCPU %u.", vcpu_id);
    return -1;
  }

  log_debug("IDTR base (vCPU %u): 0x%" PRIx64, vcpu_id, (uint64_t)idt_base);

  // Store vCPU info
  idt_table_state_add_vcpu_info(idt_data, vcpu_id, idt_base);

  const bool ia32e = (vmi_get_page_mode(vmi, vcpu_id) == VMI_PM_IA32E);
  const uint16_t gate_size = ia32e ? 16 : 8;
  const uint16_t max_vectors = 256;

  int hooked = 0;
  for (uint16_t vec = 0; vec < max_vectors; vec++) {
    addr_t handler = 0;
    const bool result =
        ia32e ? read_idt_entry_addr_ia32e(vmi, idt_base, vec, &handler)
              : read_idt_entry_addr_ia32(vmi, idt_base, vec, &handler);

    if (!result) {
      log_debug("Failed to read IDT entry %u at 0x%" PRIx64 " (vCPU %u).", vec,
                (uint64_t)(idt_base + (addr_t)vec * gate_size), vcpu_id);
      continue;
    }

    const char* name = (vec_names && vec < vec_names->len)
                           ? (const char*)g_ptr_array_index(vec_names, vec)
                           : "unknown";
    if (!name)
      name = "unknown";

    // Only report named (non-"unknown") vectors
    if (strcmp(name, "unknown") != 0) {
      const bool outside_text =
          (handler < kernel_start_addr) || (handler > kernel_end_addr);
      if (outside_text) {
        log_debug(
            "vCPU %u: Interrupt handler %s (vector %u) address changed to "
            "0x%" PRIx64,
            vcpu_id, name, vec, (uint64_t)handler);

        // Add hooked handler to data structure
        idt_table_state_add_hooked_handler(idt_data, vcpu_id, vec, name,
                                           handler, true);
        hooked++;
      } else {
        log_debug("vCPU %u: Vector %u (%s) handler at 0x%" PRIx64, vcpu_id, vec,
                  name, (uint64_t)handler);

        // Add normal handler to data structure
        idt_table_state_add_hooked_handler(idt_data, vcpu_id, vec, name,
                                           handler, false);
      }
    }
  }

  return hooked;
}

uint32_t state_idt_table_callback(vmi_instance_t vmi, void* context) {
  // Preconditions
  if (!vmi || !context) {
    return log_error_and_queue_response_task(
        "idt_table_state", STATE_IDT_TABLE, INVALID_ARGUMENTS,
        "STATE_IDT_TABLE: Invalid arguments to IDT table state callback.");
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler || !event_handler->is_paused) {
    return log_error_and_queue_response_task(
        "idt_table_state", STATE_IDT_TABLE, INVALID_ARGUMENTS,
        "STATE_IDT_TABLE: Callback requires a valid event handler context.");
  }

  log_info("Executing STATE_IDT_TABLE callback.");

  // Create IDT state data structure
  idt_table_state_data_t* idt_data = idt_table_state_data_new();
  if (!idt_data) {
    return log_error_and_queue_response_task(
        "idt_table_state", STATE_IDT_TABLE, MEMORY_ALLOCATION_FAILURE,
        "STATE_IDT_TABLE: Failed to allocate memory for IDT state data.");
  }

  // Resolve kernel text bounds
  addr_t kernel_start_addr = 0, kernel_end_addr = 0;
  if (get_kernel_text_section_range(vmi, &kernel_start_addr,
                                    &kernel_end_addr) != VMI_SUCCESS) {
    idt_table_state_data_free(idt_data);
    return log_error_and_queue_response_task(
        "idt_table_state", STATE_IDT_TABLE, VMI_OP_FAILURE,
        "STATE_IDT_TABLE: Failed to resolve kernel text section range.");
  }

  idt_table_state_set_kernel_range(idt_data, kernel_start_addr,
                                   kernel_end_addr);

  log_info("STATE_IDT_TABLE: Kernel text range: [0x%" PRIx64 ", 0x%" PRIx64
           "].",
           (uint64_t)kernel_start_addr, (uint64_t)kernel_end_addr);

  // Get number of vCPUs
  unsigned int num_vcpus = vmi_get_num_vcpus(vmi);
  if (num_vcpus == 0) {
    idt_table_state_data_free(idt_data);
    return log_error_and_queue_response_task(
        "idt_table_state", STATE_IDT_TABLE, VMI_OP_FAILURE,
        "STATE_IDT_TABLE: Failed to get number of vCPUs or no vCPUs "
        "available.");
  }

  log_info("Checking IDT on %u vCPU(s).", num_vcpus);

  // Load vector names (never NULL; defaults to "unknown")
  GPtrArray* vec_names = load_interrupt_index_table(INTERRUPT_INDEX_FILE);
  if (!vec_names || vec_names->len != 256) {
    log_warn(
        "STATE_IDT_TABLE: Interrupt index table not fully initialized; "
        "proceeding with "
        "best-effort.");
  }

  int total_hooked = 0;
  bool vcpu_inconsistency = false;
  addr_t first_idt_base = 0;

  for (unsigned int cpu = 0; cpu < num_vcpus; cpu++) {
    int hooked = check_idt_for_vcpu(vmi, cpu, kernel_start_addr,
                                    kernel_end_addr, vec_names, idt_data);

    if (hooked < 0) {
      log_warn("STATE_IDT_TABLE: Skipping vCPU %u due to IDT read failure.",
               cpu);
      continue;
    }

    total_hooked += hooked;

    // Check for IDT base consistency across vCPUs
    addr_t current_idt_base = 0;
    if (vmi_get_vcpureg(vmi, &current_idt_base, IDTR_BASE, cpu) ==
        VMI_SUCCESS) {
      if (cpu == 0) {
        first_idt_base = current_idt_base;
      } else if (current_idt_base != first_idt_base) {
        log_warn("STATE_IDT_TABLE: IDT base inconsistency: vCPU %u (0x%" PRIx64
                 ") differs from vCPU 0 (0x%" PRIx64 ")",
                 cpu, (uint64_t)current_idt_base, (uint64_t)first_idt_base);
        vcpu_inconsistency = true;
      }
    }
  }

  // Set final state information
  idt_table_state_set_summary(idt_data, total_hooked, vcpu_inconsistency);

  if (total_hooked == 0) {
    log_info(
        "STATE_IDT_TABLE: No unexpected interrupt handler addresses detected.");
  } else {
    log_warn(
        "STATE_IDT_TABLE: Total interrupt handlers flagged across all vCPUs: "
        "%d",
        total_hooked);
  }

  if (vcpu_inconsistency) {
    log_warn(
        "STATE_IDT_TABLE: IDT inconsistency detected across vCPUs - possible "
        "targeted attack.");
  }

  // Clean up vector names before returning
  if (vec_names) {
    g_ptr_array_free(vec_names, TRUE);
  }

  log_info("STATE_IDT_TABLE callback completed.");

  return log_success_and_queue_response_task(
      "idt_table_state", STATE_IDT_TABLE, idt_data,
      (void (*)(void*))idt_table_state_data_free);
}