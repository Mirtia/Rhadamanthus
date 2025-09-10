#include "event_callbacks/responses/idt_write_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

// NOLINTNEXTLINE
idt_write_data_t* idt_write_data_new(uint32_t vcpu_id, uint64_t rip,
                                     uint64_t rsp, uint64_t cr3,
                                     uint64_t write_gla, uint64_t write_gpa) {
  idt_write_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for IDT write data.");
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

void idt_write_data_free(idt_write_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL idt_write_data_t pointer.");
    return;
  }
  g_free(data);
}

cJSON* idt_write_data_to_json(const idt_write_data_t* data) {
  if (!data) {
    log_error("Invalid idt_write_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for IDT write data.");
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