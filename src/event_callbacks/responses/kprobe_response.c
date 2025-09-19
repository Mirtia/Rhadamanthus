#include "event_callbacks/responses/kprobe_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

// NOLINTNEXTLINE
kprobe_data_t* kprobe_data_new(uint32_t vcpu_id, uint64_t rip, uint64_t rsp,
                               uint64_t cr3, vmi_pid_t pid, addr_t kaddr,
                               const char* symname, const char* probe_type,
                               const char* target_symbol, addr_t target_addr) {
  kprobe_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for kprobe_data_t.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->pid = pid;
  data->kaddr = kaddr;
  data->symname = symname ? g_strdup(symname) : NULL;
  data->probe_type = probe_type ? g_strdup(probe_type) : NULL;
  data->target_symbol = target_symbol ? g_strdup(target_symbol) : NULL;
  data->target_addr = target_addr;

  return data;
}

/**
 * @brief Free a kprobe data object (safe on NULL).
 * 
 * @param data Pointer to the object to free (may be NULL).
 */
void kprobe_data_free(kprobe_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL kprobe_data_t pointer.");
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
  g_free(data);
}

/**
 * @brief Convert kprobe data to JSON format
 * 
 * @param data Pointer to the kprobe data to convert
 * @return cJSON object containing the data, or NULL on failure
 */
cJSON* kprobe_data_to_json(const kprobe_data_t* data) {
  if (!data) {
    log_error("Invalid kprobe_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for kprobe data.");
    return NULL;
  }

  // Basic info
  cJSON_AddNumberToObject(root, "vcpu_id", (double)data->vcpu_id);
  cJSON_AddNumberToObject(root, "pid", (double)data->pid);

  // Registers
  cJSON* regs = cJSON_CreateObject();
  if (!regs) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "regs", regs);
  cjson_add_hex_u64(regs, "rip", data->rip);
  cjson_add_hex_u64(regs, "rsp", data->rsp);
  cjson_add_hex_u64(regs, "cr3", data->cr3);

  // Probe information
  cJSON* probe = cJSON_CreateObject();
  if (!probe) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "probe", probe);
  cjson_add_hex_u64(probe, "address", data->kaddr);

  if (data->symname) {
    cJSON_AddStringToObject(probe, "function", data->symname);
  }
  if (data->probe_type) {
    cJSON_AddStringToObject(probe, "type", data->probe_type);
  }
  if (data->target_symbol) {
    cJSON_AddStringToObject(probe, "target_symbol", data->target_symbol);
  }
  if (data->target_addr) {
    cjson_add_hex_u64(probe, "target_address", data->target_addr);
  }

  return root;
}
