#include "event_callbacks/responses/code_section_modify_response.h"
#include <bits/stdint-uintn.h>
#include <inttypes.h>
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

code_section_modify_data_t* code_section_modify_data_new(
    // NOLINTNEXTLINE
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    addr_t write_gla, addr_t write_gpa, const char* kernel_symbol) {
  code_section_modify_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for code section modify data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->write_gla = write_gla;
  data->write_gpa = write_gpa;

  if (kernel_symbol) {
    data->kernel_symbol = g_strdup(kernel_symbol);
    if (!data->kernel_symbol) {
      log_error("Failed to allocate memory for kernel symbol.");
      g_free(data);
      return NULL;
    }
  } else {
    data->kernel_symbol = NULL;
  }

  return data;
}

void code_section_modify_data_free(code_section_modify_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL code_section_modify_data_t pointer.");
    return;
  }
  if (data->kernel_symbol) {
    g_free(data->kernel_symbol);
  }
  g_free(data);
}

cJSON* code_section_modify_data_to_json(
    const code_section_modify_data_t* data) {
  if (!data) {
    log_error("Invalid code_section_modify_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for code section modify data.");
    return NULL;
  }

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
  cjson_add_hex_addr(memory, "write_gla", data->write_gla);
  cjson_add_hex_addr(memory, "write_gpa", data->write_gpa);

  if (data->kernel_symbol) {
    cJSON_AddStringToObject(memory, "kernel_symbol", data->kernel_symbol);
  } else {
    cJSON_AddNullToObject(memory, "kernel_symbol");
  }

  return root;
}