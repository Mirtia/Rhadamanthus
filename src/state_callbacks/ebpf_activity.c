#include "state_callbacks/ebpf_activity.h"
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <log.h>
#include <stdbool.h>
#include "event_handler.h"
#include "offsets.h"
#include "state_callbacks/responses/ebpf_activity_response.h"
#include "utils.h"

/**
 * @brief Structure that holds information (the keys) of the LibVMI configuration file, usually at /etc/libvmi.conf.
 */
typedef struct {
  unsigned long tasks_offset;  //< linux_tasks
  unsigned long mm_offset;     //< linux_mm
  unsigned long pid_offset;    //< linux_pid
  unsigned long comm_offset;   //< linux_name
} config_offset_t;

/**
 * @brief BPF file operations symbols. These identify BPF anon-inode files.
 * @details See: https://elixir.bootlin.com/linux/v5.15/source/kernel/bpf/syscall.c
 */
struct bpf_fops_syms {
  addr_t prog_fops;  ///< The address of the bpf_prog_fops symbol.
  addr_t map_fops;   ///< The address of the bpf_map_fops symbol.
  addr_t link_fops;  ///< The address of the bpf_link_fops symbol.
};

static inline unsigned long get_offset_from_config(vmi_instance_t vmi,
                                                   const char* key) {
  unsigned long offset = 0;
  vmi_get_offset(vmi, key, &offset) == VMI_SUCCESS
      ? log_debug("STATE_EBPF_ARTIFACTS: offset %s = 0x%lx.", key, offset)
      : log_debug("STATE_EBPF_ARTIFACTS: offset %s not found.", key);
  return offset;
}

static void resolve_kernel_offsets(vmi_instance_t vmi,
                                   config_offset_t* config_offsets) {
  config_offsets->tasks_offset = get_offset_from_config(vmi, "linux_tasks");
  config_offsets->mm_offset = get_offset_from_config(vmi, "linux_mm");
  config_offsets->pid_offset = get_offset_from_config(vmi, "linux_pid");
  config_offsets->comm_offset = get_offset_from_config(vmi, "linux_name");

  if (!config_offsets->tasks_offset || !config_offsets->pid_offset ||
      !config_offsets->comm_offset) {
    log_error(
        "STATE_EBPF_ARTIFACTS: Required profile offsets missing "
        "(tasks=0x%lx pid=0x%lx comm=0x%lx).",
        config_offsets->tasks_offset, config_offsets->pid_offset,
        config_offsets->comm_offset);
  }
}

static void resolve_bpf_fops(vmi_instance_t vmi, struct bpf_fops_syms* s) {
  s->prog_fops = s->map_fops = s->link_fops = 0;
  vmi_translate_ksym2v(vmi, "bpf_prog_fops", &s->prog_fops);
  vmi_translate_ksym2v(vmi, "bpf_map_fops", &s->map_fops);
  vmi_translate_ksym2v(vmi, "bpf_link_fops", &s->link_fops);
}

static inline int xa_is_value(addr_t e) {
  return (e & 1UL) != 0;
}

static inline int xa_is_internal(addr_t e) {
  return (e & 3UL) == 2UL;
}

static inline int xa_is_node(addr_t e) {
  return xa_is_internal(e) && e > 4096;
}

static inline addr_t xa_to_node(addr_t e) {
  return e - 2UL;
}

static inline addr_t xa_untag_pointer(addr_t e) {
  return e & ~3UL;
}

static uint64_t xa_dfs_count_collect(vmi_instance_t vmi, addr_t node_va,
                                     uint64_t* mismatch_guard, addr_t* out_buf,
                                     uint32_t* io_cap, uint32_t* io_len) {
  uint8_t count_field = 0;
  if (vmi_read_8_va(vmi, node_va + LINUX_OFF_XA_NODE_COUNT, 0, &count_field) !=
      VMI_SUCCESS) {
    log_warn("XArray: cannot read count field at 0x%lx.",
             (unsigned long)(node_va + LINUX_OFF_XA_NODE_COUNT));
    return 0;
  }

  uint64_t total = 0;
  uint32_t observed_nonnull = 0;

  for (uint32_t i = 0; i < (uint32_t)LINUX_XA_CHUNK_SIZE; i++) {
    addr_t slot_ptr =
        node_va + LINUX_OFF_XA_NODE_SLOTS + (addr_t)i * sizeof(addr_t);
    addr_t entry = 0;

    if (vmi_read_addr_va(vmi, slot_ptr, 0, &entry) != VMI_SUCCESS || !entry) {
      // Noisy debug.
      // log_debug("XArray: empty slot at 0x%lx", (unsigned long)slot_ptr);
      continue;
    }
    observed_nonnull++;

    if (xa_is_internal(entry)) {
      if (xa_is_node(entry)) {
        total += xa_dfs_count_collect(vmi, xa_to_node(entry), mismatch_guard,
                                      out_buf, io_cap, io_len);
      }
      continue;
    }

    if (xa_is_value(entry)) {
      if (out_buf && io_len && io_cap && *io_len < *io_cap) {
        out_buf[(*io_len)++] = entry;
      }
      total++;
    } else {
      addr_t obj = xa_untag_pointer(entry);
      if (out_buf && io_len && io_cap && *io_len < *io_cap) {
        out_buf[(*io_len)++] = obj;
      }
      total++;
    }
  }

  if (observed_nonnull > (uint32_t)count_field + 8) {
    (*mismatch_guard)++;
  }
  return total;
}

static uint64_t idr_count_collect(vmi_instance_t vmi, addr_t idr_va,
                                  addr_t* out_buf, uint32_t* cap,
                                  uint32_t* len) {
  addr_t xarray_va = idr_va + LINUX_OFF_IDR_RT;
  addr_t xa_head = 0;

  if (vmi_read_addr_va(vmi, xarray_va + LINUX_OFF_XARRAY_XA_HEAD, 0,
                       &xa_head) != VMI_SUCCESS ||
      !xa_head) {
    log_debug("XArray: cannot read head at 0x%lx.",
              (unsigned long)(xarray_va + LINUX_OFF_XARRAY_XA_HEAD));
    return 0;
  }

  if (!xa_is_internal(xa_head)) {
    addr_t obj = xa_untag_pointer(xa_head);
    if (out_buf && len && cap && *len < *cap) {
      out_buf[(*len)++] = obj;
    }
    return 1;
  }

  if (xa_is_node(xa_head)) {
    uint64_t guard = 0;
    uint64_t n = xa_dfs_count_collect(vmi, xa_to_node(xa_head), &guard, out_buf,
                                      cap, len);
    if (guard) {
      log_warn(
          "XArray: possible chunk-size mismatch; try LINUX_XA_CHUNK_SIZE=16.");
    }
    return n;
  }
  return 0;
}

static void report_idr(vmi_instance_t vmi, const char* label, const char* sym,
                       int collect) {
  addr_t idr = 0;
  if (vmi_translate_ksym2v(vmi, sym, &idr) != VMI_SUCCESS) {
    log_debug("STATE_EBPF_ARTIFACTS: symbol '%s' not found (%s).", sym, label);
    return;
  }

  addr_t buf[256];
  uint32_t cap = collect ? (uint32_t)(sizeof(buf) / sizeof(buf[0])) : 0;
  uint32_t len = 0;
  uint64_t n = idr_count_collect(vmi, idr, collect ? buf : NULL,
                                 collect ? &cap : NULL, collect ? &len : NULL);

  log_info("STATE_EBPF_ARTIFACTS: %s = %" PRIu64, label, n);

  if (collect && len) {
    uint32_t dump = len < 10 ? len : 10;
    for (uint32_t i = 0; i < dump; i++) {
      log_debug("%s[%u] = 0x%lx.", label, i, (unsigned long)buf[i]);
    }
  }
}

static int maybe_print_bpf_file(vmi_instance_t vmi, int32_t tgid,
                                const char comm[LINUX_TASK_COMM_LEN],
                                addr_t file_va, const struct bpf_fops_syms* s,
                                ebpf_activity_state_data_t* data) {

  // file->f_op == &bpf_*_fops => file->private_data points to bpf_{prog,map,link}.
  // References:
  //   Layout: https://elixir.bootlin.com/linux/v5.15/source/include/linux/fdtable.h
  //   /proc/<pid>/fdinfo fields: see fs/proc/fd.c
  //   bpf inodes: https://elixir.bootlin.com/linux/v5.15/source/kernel/bpf/syscall.c

  addr_t fops = 0;
  if (vmi_read_addr_va(vmi, file_va + LINUX_OFF_FILE_F_OP, 0, &fops) !=
          VMI_SUCCESS ||
      !fops) {
    return 0;
  }

  addr_t priv = 0;
  vmi_read_addr_va(vmi, file_va + LINUX_OFF_FILE_PRIVATE_DATA, 0, &priv);

  if (s->map_fops && fops == s->map_fops) {
    uint32_t id = 0;
    vmi_read_32_va(vmi, priv + LINUX_BPF_MAP_ID_OFFSET, 0, &id);
    log_info("[PID %d] %-8s FD->BPF-MAP: file=0x%lx map=0x%lx id=%u.",
             (int)tgid, comm, (unsigned long)file_va, (unsigned long)priv, id);

    if (data) {
      ebpf_activity_state_add_map(data, id, (uint64_t)priv, (uint32_t)tgid,
                                  comm);
    }
    return 1;
  }

  if (s->prog_fops && fops == s->prog_fops) {
    addr_t aux = 0;
    uint32_t id = 0;
    char pname[LINUX_BPF_OBJ_NAME_LEN + 1] = {0};

    if (priv &&
        vmi_read_addr_va(vmi, priv + LINUX_BPF_PROG_AUX_OFFSET, 0, &aux) ==
            VMI_SUCCESS &&
        aux) {
      vmi_read_32_va(vmi, aux + LINUX_BPF_PROG_AUX_ID_OFFSET, 0, &id);
      vmi_read_va(vmi, aux + LINUX_BPF_PROG_AUX_NAME_OFFSET, 0,
                  LINUX_BPF_OBJ_NAME_LEN, pname, NULL);
      pname[LINUX_BPF_OBJ_NAME_LEN] = '\0';
    }

    log_info(
        "[PID %d] %-8s FD->BPF-PROG: file=0x%lx prog=0x%lx aux=0x%lx id=%u "
        "name='%s'",
        (int)tgid, comm, (unsigned long)file_va, (unsigned long)priv,
        (unsigned long)aux, id, pname);

    if (data) {
      ebpf_activity_state_add_program(data, id, "unknown", pname, "unknown",
                                      (uint64_t)priv, (uint64_t)aux,
                                      (uint32_t)tgid, comm);
      ebpf_activity_state_add_attachment_point(data, "unknown", id);
    }
    return 1;
  }

  if (s->link_fops && fops == s->link_fops) {
    uint32_t id = 0;
    vmi_read_32_va(vmi, priv + LINUX_OFF_BPF_LINK_ID, 0, &id);
    log_info("[PID %d] %-8s FD->BPF-LINK: file=0x%lx link=0x%lx id=%u.",
             (int)tgid, comm, (unsigned long)file_va, (unsigned long)priv, id);

    if (data) {
      ebpf_activity_state_add_link(data, id, (uint64_t)priv, (uint32_t)tgid,
                                   comm);
    }
    return 1;
  }

  return 0;
}

static inline addr_t task_from_listnode(const config_offset_t* config_offsets,
                                        addr_t list_node_addr) {
  return list_node_addr - (addr_t)config_offsets->tasks_offset;
}

static void scan_task_bpf_fds(vmi_instance_t vmi,
                              const config_offset_t* config_offsets,
                              addr_t task_va, const struct bpf_fops_syms* s,
                              ebpf_activity_state_data_t* data) {
  int32_t tgid = -1, pid = -1;
  char comm[LINUX_TASK_COMM_LEN] = {0};

  if (vmi_read_32_va(vmi, task_va + config_offsets->pid_offset, 0,
                     (uint32_t*)&pid) != VMI_SUCCESS) {
    log_debug("STATE_EBPF_ARTIFACTS: cannot read pid at 0x%lx.",
              (unsigned long)(task_va + config_offsets->pid_offset));
    return;
  }
  if (vmi_read_32_va(vmi, task_va + LINUX_OFF_TASK_TGID, 0, (uint32_t*)&tgid) !=
      VMI_SUCCESS) {
    log_debug("STATE_EBPF_ARTIFACTS: cannot read tgid at 0x%lx.",
              (unsigned long)(task_va + LINUX_OFF_TASK_TGID));
    return;
  }

  if (vmi_read_va(vmi, task_va + config_offsets->comm_offset, 0, sizeof(comm),
                  comm, NULL) != VMI_SUCCESS) {
    log_debug("STATE_EBPF_ARTIFACTS: cannot read comm at 0x%lx.",
              (unsigned long)(task_va + config_offsets->comm_offset));
    return;
  }

  addr_t files = 0;
  if (vmi_read_addr_va(vmi, task_va + LINUX_OFF_TASK_FILES, 0, &files) !=
          VMI_SUCCESS ||
      !files) {
    log_debug(
        "STATE_EBPF_ARTIFACTS: PID %d (tgid=%d, comm='%s') has no "
        "files_struct.",
        pid, tgid, comm);
    return;
  }

  addr_t fdt = 0;
  if (vmi_read_addr_va(vmi, files + LINUX_OFF_FILES_FDT, 0, &fdt) !=
          VMI_SUCCESS ||
      !fdt) {
    log_debug(
        "STATE_EBPF_ARTIFACTS: PID %d (tgid=%d, comm='%s') has no fdtable.",
        pid, tgid, comm);
    return;
  }

  uint32_t max_fds = 0;
  if (vmi_read_32_va(vmi, fdt + LINUX_OFF_FDTABLE_MAXFDS, 0, &max_fds) !=
          VMI_SUCCESS ||
      !max_fds) {
    log_debug("STATE_EBPF_ARTIFACTS: PID %d (tgid=%d, comm='%s') has no FDs.",
              pid, tgid, comm);
    return;
  }

  addr_t fd_array = 0;
  if (vmi_read_addr_va(vmi, fdt + LINUX_OFF_FDTABLE_FD, 0, &fd_array) !=
          VMI_SUCCESS ||
      !fd_array) {
    log_debug(
        "STATE_EBPF_ARTIFACTS: PID %d (tgid=%d, comm='%s') has no FD array.",
        pid, tgid, comm);
    return;
  }

  int hits = 0;
  for (uint32_t i = 0; i < max_fds; i++) {
    addr_t file_ptr = fd_array + (addr_t)i * sizeof(addr_t);
    addr_t file_va = 0;

    if (vmi_read_addr_va(vmi, file_ptr, 0, &file_va) != VMI_SUCCESS ||
        !file_va) {
      continue;
    }

    hits += maybe_print_bpf_file(vmi, tgid, comm, file_va, s, data);
  }

  if (hits > 0) {
    log_debug("PID %d [tgid=%d, comm='%s']: %d BPF FDs", pid, tgid, comm, hits);
  }
}

static void scan_all_tasks_for_bpf(vmi_instance_t vmi,
                                   const config_offset_t* config_offsets,
                                   ebpf_activity_state_data_t* data) {
  addr_t init_task = 0;
  if (vmi_translate_ksym2v(vmi, "init_task", &init_task) != VMI_SUCCESS ||
      !init_task) {
    log_debug("STATE_EBPF_ARTIFACTS: init_task not found; cannot walk PIDs.");
    return;
  }

  struct bpf_fops_syms symbols = {0};
  resolve_bpf_fops(vmi, &symbols);

  addr_t head = init_task + config_offsets->tasks_offset;
  addr_t cur = 0;
  if (vmi_read_addr_va(vmi, head, 0, &cur) != VMI_SUCCESS || !cur) {
    return;
  }

  addr_t guard = 0, guard_max = 0;
  // get pid_max (read kernel symbol)
  if (vmi_translate_ksym2v(vmi, "pid_max", &guard_max) != VMI_SUCCESS) {
    guard_max = 65536;  // fallback value LINUX_PID_MAX_DEFAULT
  }
  while (cur != head && guard++ < guard_max) {
    addr_t task = task_from_listnode(config_offsets, cur);
    scan_task_bpf_fds(vmi, config_offsets, task, &symbols, data);

    if (vmi_read_addr_va(vmi, cur, 0, &cur) != VMI_SUCCESS || !cur) {
      break;
    }
  }
}

uint32_t state_ebpf_activity_callback(vmi_instance_t vmi, void* context) {
  if (!vmi || !context) {
    return log_error_and_queue_response_task(
        "ebpf_activity_state", STATE_EBPF_ARTIFACTS, INVALID_ARGUMENTS,
        "STATE_EBPF_ACTIVITY: Invalid parameters");
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler->is_paused) {
    return log_error_and_queue_response_task(
        "ebpf_activity_state", STATE_EBPF_ARTIFACTS, INVALID_ARGUMENTS,
        "STATE_EBPF_ACTIVITY: VM must be paused");
  }

  log_info("Executing STATE_EBPF_ACTIVITY callback.");

  // Create eBPF activity state data structure
  ebpf_activity_state_data_t* activity_data = ebpf_activity_state_data_new();
  if (!activity_data) {
    return log_error_and_queue_response_task(
        "ebpf_activity_state", STATE_EBPF_ARTIFACTS, MEMORY_ALLOCATION_FAILURE,
        "STATE_EBPF_ARTIFACTS: Failed to allocate memory for eBPF activity "
        "state data");
  }

  config_offset_t config_offsets = {0};
  resolve_kernel_offsets(vmi, &config_offsets);

  addr_t bpf_presence = 0;
  if (vmi_translate_ksym2v(vmi, "bpf_verifier_log_write", &bpf_presence) ==
      VMI_SUCCESS) {
    log_info("STATE_EBPF_ARTIFACTS: BPF verifier present.");
  }
  if (vmi_translate_ksym2v(vmi, "bpf_prog_load", &bpf_presence) ==
      VMI_SUCCESS) {
    log_info("STATE_EBPF_ARTIFACTS: BPF program loader present.");
  }

  report_idr(vmi, "BPF programs [prog_idr]", "prog_idr", 0);
  report_idr(vmi, "BPF maps [map_idr]", "map_idr", 0);
  report_idr(vmi, "BPF links [link_idr]", "link_idr", 0);
  report_idr(vmi, "BTF objects [btf_idr]", "btf_idr", 0);

  // Per-PID association via FD tables
  log_info("STATE_EBPF_ACTIVITY: Scanning per-PID BPF FDs...");
  scan_all_tasks_for_bpf(vmi, &config_offsets, activity_data);

  // Set summary information
  uint32_t total_programs = activity_data->loaded_programs->len;
  uint32_t total_maps = activity_data->maps->len;
  uint32_t total_links = activity_data->links->len;
  uint32_t total_btf_objects =
      0;  // Not currently tracked in this implementation
  uint32_t processes_with_ebpf = 0;  // Could be calculated from unique PIDs

  ebpf_activity_state_set_summary(activity_data, total_programs, total_maps,
                                  total_links, total_btf_objects,
                                  processes_with_ebpf);

  log_info("STATE_EBPF_ACTIVITY: Found %u programs, %u maps, %u links",
           total_programs, total_maps, total_links);

  int result = log_success_and_queue_response_task(
      "ebpf_activity_state", STATE_EBPF_ARTIFACTS, activity_data,
      (void (*)(void*))ebpf_activity_state_data_free);

  log_info("STATE_EBPF_ACTIVITY callback completed.");
  return result;
}