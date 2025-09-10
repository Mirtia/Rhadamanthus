#include "event_callbacks/responses/ebpf_probe_response.h"
#include <inttypes.h>
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

ebpf_probe_data_t* ebpf_probe_data_new(
    // NOLINTNEXTLINE
    uint32_t vcpu_id,     ///< Virtual CPU identifier where the event occurred
    uint64_t rip,         ///< Instruction pointer register value
    uint64_t rsp,         ///< Stack pointer register value
    uint64_t cr3,         ///< Control register 3 value (page table base)
    vmi_pid_t pid,        ///< Process identifier (0 if unknown)
    addr_t kaddr,         ///< Kernel address where the probe was inserted
    const char* symname,  ///< Function name being probed (can be NULL)
    const char*
        probe_type,  ///< Type of probe (kprobe, uprobe, bpf_prog, tracepoint)
    const char*
        target_symbol,  ///< Target symbol name for kprobe/kretprobe (can be NULL)
    // NOLINTNEXTLINE
    addr_t target_addr,  ///< Target address for kprobe/kretprobe (0 if unknown)
    uint32_t
        attach_type,  ///< BPF attach type for bpf_prog probes (0 if not applicable)
    const char*
        tracepoint_name) {  ///< Tracepoint name for tracepoint probes (can be NULL)
  ebpf_probe_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for eBPF probe data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->pid = pid;
  data->kaddr = kaddr;
  data->target_addr = target_addr;
  data->attach_type = attach_type;

  if (symname) {
    data->symname = g_strdup(symname);
    if (!data->symname) {
      log_error("Failed to allocate memory for symname.");
      g_free(data);
      return NULL;
    }
  } else {
    data->symname = NULL;
  }

  if (probe_type) {
    data->probe_type = g_strdup(probe_type);
    if (!data->probe_type) {
      log_error("Failed to allocate memory for probe_type.");
      if (data->symname)
        g_free(data->symname);
      g_free(data);
      return NULL;
    }
  } else {
    data->probe_type = NULL;
  }

  if (target_symbol) {
    data->target_symbol = g_strdup(target_symbol);
    if (!data->target_symbol) {
      log_error("Failed to allocate memory for target_symbol.");
      if (data->symname)
        g_free(data->symname);
      if (data->probe_type)
        g_free(data->probe_type);
      g_free(data);
      return NULL;
    }
  } else {
    data->target_symbol = NULL;
  }

  if (tracepoint_name) {
    data->tracepoint_name = g_strdup(tracepoint_name);
    if (!data->tracepoint_name) {
      log_error("Failed to allocate memory for tracepoint_name.");
      if (data->symname)
        g_free(data->symname);
      if (data->probe_type)
        g_free(data->probe_type);
      if (data->target_symbol)
        g_free(data->target_symbol);
      g_free(data);
      return NULL;
    }
  } else {
    data->tracepoint_name = NULL;
  }

  return data;
}

void ebpf_probe_data_free(ebpf_probe_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL ebpf_probe_data_t pointer.");
    return;
  }
  if (data->symname) {
    g_free(data->symname);
  }
  if (data->probe_type) {
    g_free(data->probe_type);
  }
  if (data->target_symbol) {
    g_free(data->target_symbol);
  }
  if (data->tracepoint_name) {
    g_free(data->tracepoint_name);
  }
  g_free(data);
}

cJSON* ebpf_probe_data_to_json(const ebpf_probe_data_t* data) {
  if (!data) {
    log_error("Invalid ebpf_probe_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for eBPF probe data.");
    return NULL;
  }

  cJSON_AddNumberToObject(root, "vcpu_id", (double)data->vcpu_id);
  cJSON_AddNumberToObject(root, "pid", (double)data->pid);

  cJSON* regs = cJSON_CreateObject();
  if (!regs) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "regs", regs);
  cjson_add_hex_u64(regs, "rip", data->rip);
  cjson_add_hex_u64(regs, "rsp", data->rsp);
  cjson_add_hex_u64(regs, "cr3", data->cr3);

  cJSON* ebpf_probe = cJSON_CreateObject();
  if (!ebpf_probe) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "ebpf_probe", ebpf_probe);

  cjson_add_hex_addr(ebpf_probe, "kaddr", data->kaddr);

  if (data->symname) {
    cJSON_AddStringToObject(ebpf_probe, "symname", data->symname);
  } else {
    cJSON_AddNullToObject(ebpf_probe, "symname");
  }

  if (data->probe_type) {
    cJSON_AddStringToObject(ebpf_probe, "probe_type", data->probe_type);
  } else {
    cJSON_AddNullToObject(ebpf_probe, "probe_type");
  }

  if (data->target_symbol) {
    cJSON_AddStringToObject(ebpf_probe, "target_symbol", data->target_symbol);
  } else {
    cJSON_AddNullToObject(ebpf_probe, "target_symbol");
  }

  if (data->target_addr) {
    cjson_add_hex_addr(ebpf_probe, "target_addr", data->target_addr);
  } else {
    cJSON_AddNullToObject(ebpf_probe, "target_addr");
  }

  if (data->attach_type) {
    cJSON_AddNumberToObject(ebpf_probe, "attach_type",
                            (double)data->attach_type);
  } else {
    cJSON_AddNullToObject(ebpf_probe, "attach_type");
  }

  if (data->tracepoint_name) {
    cJSON_AddStringToObject(ebpf_probe, "tracepoint_name",
                            data->tracepoint_name);
  } else {
    cJSON_AddNullToObject(ebpf_probe, "tracepoint_name");
  }

  return root;
}