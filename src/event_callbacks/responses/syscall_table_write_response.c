#include "event_callbacks/responses/syscall_table_write_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

syscall_table_write_data_t* syscall_table_write_data_new(
    // NOLINTNEXTLINE
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t write_gla, uint64_t write_gpa, uint32_t syscall_number,
    const char* syscall_name) {
  syscall_table_write_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for syscall table write data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->write_gla = write_gla;
  data->write_gpa = write_gpa;
  data->syscall_number = syscall_number;
  data->syscall_name = syscall_name ? g_strdup(syscall_name) : NULL;

  return data;
}

void syscall_table_write_data_free(syscall_table_write_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL syscall_table_write_data_t pointer.");
    return;
  }
  if (data->syscall_name) {
    g_free(data->syscall_name);
  }
  g_free(data);
}

cJSON* syscall_table_write_data_to_json(
    const syscall_table_write_data_t* data) {
  if (!data) {
    log_error("Invalid syscall_table_write_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for syscall table write data.");
    return NULL;
  }

  // vcpu_id as a JSON number (cJSON stores numbers as doubles)
  cJSON_AddNumberToObject(root, "vcpu_id", (double)data->vcpu_id);

  cJSON* regs = cJSON_CreateObject();
  if (!regs) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "regs", regs);
  cjson_add_hex_u64(regs, "rip", data->rip);
  cjson_add_hex_u64(regs, "rsp", data->rsp);
  cjson_add_hex_u64(regs, "cr3", data->cr3);

  cJSON* memory = cJSON_CreateObject();
  if (!memory) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "memory", memory);
  cjson_add_hex_u64(memory, "write_gla", data->write_gla);
  cjson_add_hex_u64(memory, "write_gpa", data->write_gpa);

  // Add syscall information
  cJSON_AddNumberToObject(root, "syscall_number", (double)data->syscall_number);
  if (data->syscall_name) {
    cJSON_AddStringToObject(root, "syscall_name", data->syscall_name);
  } else {
    cJSON_AddStringToObject(root, "syscall_name", "unknown");
  }

  return root;
}