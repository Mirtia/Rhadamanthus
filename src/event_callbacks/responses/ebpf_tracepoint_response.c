#include "event_callbacks/responses/ebpf_tracepoint_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

// NOLINTNEXTLINE
ebpf_tracepoint_data_t* ebpf_tracepoint_data_new(
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3, vmi_pid_t pid,
    addr_t kaddr, const char* symname, const char* program_type,
    uint32_t attach_type, const char* tracepoint_name) {
  ebpf_tracepoint_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for ebpf_tracepoint_data_t.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->pid = pid;
  data->kaddr = kaddr;
  data->symname = symname ? g_strdup(symname) : NULL;
  data->program_type = program_type ? g_strdup(program_type) : NULL;
  data->attach_type = attach_type;
  data->tracepoint_name = tracepoint_name ? g_strdup(tracepoint_name) : NULL;

  return data;
}

/**
 * @brief Free an eBPF tracepoint data object (safe on NULL).
 * 
 * @param data Pointer to the object to free (may be NULL).
 */
void ebpf_tracepoint_data_free(ebpf_tracepoint_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL ebpf_tracepoint_data_t pointer.");
    return;
  }
  if (data->symname) {
    g_free(data->symname);
  }
  if (data->program_type) {
    g_free(data->program_type);
  }
  if (data->tracepoint_name) {
    g_free(data->tracepoint_name);
  }
  g_free(data);
}

/**
 * @brief Convert eBPF tracepoint data to JSON format
 * 
 * @param data Pointer to the eBPF tracepoint data to convert
 * @return cJSON object containing the data, or NULL on failure
 */
cJSON* ebpf_tracepoint_data_to_json(const ebpf_tracepoint_data_t* data) {
  if (!data) {
    log_error("Invalid ebpf_tracepoint_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for eBPF tracepoint data.");
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

  // Program information
  cJSON* program = cJSON_CreateObject();
  if (!program) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "program", program);
  cjson_add_hex_u64(program, "address", data->kaddr);

  if (data->symname) {
    cJSON_AddStringToObject(program, "function", data->symname);
  }
  if (data->program_type) {
    cJSON_AddStringToObject(program, "type", data->program_type);
  }
  if (data->attach_type) {
    cJSON_AddNumberToObject(program, "attach_type", (double)data->attach_type);
  }
  if (data->tracepoint_name) {
    cJSON_AddStringToObject(program, "tracepoint_name", data->tracepoint_name);
  }

  return root;
}
