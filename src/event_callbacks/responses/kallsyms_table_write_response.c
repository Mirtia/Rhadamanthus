#include "event_callbacks/responses/kallsyms_table_write_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

kallsyms_table_write_data_t* kallsyms_table_write_data_new(
    // NOLINTNEXTLINE
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t write_gla, uint64_t write_gpa) {
  kallsyms_table_write_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for kallsyms table write data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->write_gla = write_gla;
  data->write_gpa = write_gpa;

  return data;
}

void kallsyms_table_write_data_free(kallsyms_table_write_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL kallsyms_table_write_data_t pointer.");
    return;
  }
  g_free(data);
}

cJSON* kallsyms_table_write_data_to_json(
    const kallsyms_table_write_data_t* data) {
  if (!data) {
    log_error("Invalid kallsyms_table_write_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for kallsyms table write data.");
    return NULL;
  }

  // vcpu_id as a JSON number
  cJSON_AddNumberToObject(root, "vcpu_id", (double)data->vcpu_id);

  // Register values
  cJSON* regs = cJSON_CreateObject();
  if (!regs) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "regs", regs);
  cjson_add_hex_u64(regs, "rip", data->rip);
  cjson_add_hex_u64(regs, "rsp", data->rsp);
  cjson_add_hex_u64(regs, "cr3", data->cr3);

  // Memory information
  cJSON* memory = cJSON_CreateObject();
  if (!memory) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "memory", memory);
  cjson_add_hex_u64(memory, "write_gla", data->write_gla);
  cjson_add_hex_u64(memory, "write_gpa", data->write_gpa);

  return root;
}