#include "state_callbacks/ebpf_activity.h"
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <log.h>
#include "event_handler.h"

uint32_t state_ebpf_activity_callback(vmi_instance_t vmi, void* context) {
  /* Preconditions */
  if (!vmi || !context) {
    log_error("STATE_EBPF_ARTIFACTS: invalid parameters.");
    return VMI_FAILURE;
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler->is_paused) {
    log_error("STATE_EBPF_ARTIFACTS: VM must be paused.");
    return VMI_FAILURE;
  }

  log_info("Executing STATE_EBPF_ARTIFACTS callback.");

  const char* sym_stats = "bpf_stats_enabled";
  int stats_enabled = -1;
  addr_t virtual_addr = 0;
  if (vmi_translate_ksym2v(vmi, sym_stats, &virtual_addr) == VMI_SUCCESS &&
      virtual_addr) {
    uint32_t raw = 0;
    if (vmi_read_32_va(vmi, virtual_addr, 0, &raw) == VMI_SUCCESS) {
      stats_enabled = (int32_t)raw;
    } else {
      log_debug("STATE_EBPF_ARTIFACTS: failed to read %s @0x%" PRIx64,
                sym_stats, (uint64_t)virtual_addr);
    }
  } else {
    log_debug("STATE_EBPF_ARTIFACTS: symbol '%s' not found.", sym_stats);
  }

  if (stats_enabled == 1) {
    log_info("STATE_EBPF_ARTIFACTS: bpf_stats_enabled=1 (BPF statistics ON).");
  } else if (stats_enabled == 0) {
    log_debug("STATE_EBPF_ARTIFACTS: bpf_stats_enabled=0.");
  } else {
    log_debug("STATE_EBPF_ARTIFACTS: bpf_stats_enabled unavailable.");
  }

  // bpf_prog_active is a per-CPU counter showing active BPF programs currently executing.
  const char* sym_active = "bpf_prog_active";
  const char* sym_per_cpu = "__per_cpu_offset";
  const char* sym_nr_cpu = "nr_cpu_ids";

  long active_sum = -1;
  addr_t active_va = 0;
  addr_t percpu_offsets_va = 0;

  if (vmi_translate_ksym2v(vmi, sym_active, &active_va) == VMI_SUCCESS &&
      active_va &&
      vmi_translate_ksym2v(vmi, sym_per_cpu, &percpu_offsets_va) ==
          VMI_SUCCESS &&
      percpu_offsets_va) {

    uint32_t cpu_count = 256;
    addr_t nr_cpu_ids_va = 0;
    if (vmi_translate_ksym2v(vmi, sym_nr_cpu, &nr_cpu_ids_va) == VMI_SUCCESS &&
        nr_cpu_ids_va) {
      uint32_t num = 0;
      if (vmi_read_32_va(vmi, nr_cpu_ids_va, 0, &num) == VMI_SUCCESS &&
          num > 0 && num <= 4096) {
        cpu_count = num;
      }
    }

    long sum = 0;
    for (uint32_t cpu = 0; cpu < cpu_count; cpu++) {
      uint64_t base_off = 0;
      addr_t entry_va = percpu_offsets_va + (addr_t)cpu * sizeof(uint64_t);
      if (vmi_read_64_va(vmi, entry_va, 0, &base_off) != VMI_SUCCESS) {
        continue;
      }

      addr_t this_cpu_va = (addr_t)base_off + active_va;

      uint32_t raw = 0;
      if (vmi_read_32_va(vmi, this_cpu_va, 0, &raw) == VMI_SUCCESS) {
        sum += (long)(int32_t)raw;
      }
    }
    active_sum = sum;
  } else {
    log_debug("STATE_EBPF_ARTIFACTS: '%s' or '%s' not found.", sym_active,
              sym_per_cpu);
  }

  if (active_sum >= 0) {
    if (active_sum > 0) {
      log_warn(
          "STATE_EBPF_ARTIFACTS: eBPF live activity detected "
          "(sum(bpf_prog_active)=%ld).",
          active_sum);
    } else {
      log_info(
          "STATE_EBPF_ARTIFACTS: no live eBPF activity detected "
          "(sum(bpf_prog_active)=0).");
    }
  } else {
    log_debug("STATE_EBPF_ARTIFACTS: bpf_prog_active unavailable.");
  }

  log_info("STATE_EBPF_ARTIFACTS callback completed.");
  return VMI_SUCCESS;
}
