#include "event_callbacks/responses/ftrace_hook_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

// NOLINTNEXTLINE
ftrace_hook_data_t* ftrace_hook_data_new(
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3, uint64_t rflags,
    uint64_t gla, uint64_t gpa, const char* symname, uint64_t original_value,
    uint64_t current_value, const char* value_type,
    const char* modification_type) {
  ftrace_hook_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for ftrace_hook_data_t.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->rflags = rflags;
  data->gla = gla;
  data->gpa = gpa;
  data->symname = symname ? g_strdup(symname) : NULL;
  data->original_value = original_value;
  data->current_value = current_value;
  data->value_type = value_type ? g_strdup(value_type) : NULL;
  data->modification_type =
      modification_type ? g_strdup(modification_type) : NULL;

  return data;
}

/**
 * @brief Free a ftrace hook data object (safe on NULL).
 * 
 * @param data Pointer to the object to free (may be NULL).
 */
void ftrace_hook_data_free(ftrace_hook_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL ftrace_hook_data_t pointer.");
    return;
  }
  if (data->symname) {
    g_free(data->symname);
  }
  if (data->value_type) {
    g_free(data->value_type);
  }
  if (data->modification_type) {
    g_free(data->modification_type);
  }
  g_free(data);
}

/**
 * @brief Convert ftrace hook data to JSON format
 * 
 * @param data Pointer to the ftrace hook data to convert
 * @return cJSON object containing the data, or NULL on failure
 */
cJSON* ftrace_hook_data_to_json(const ftrace_hook_data_t* data) {
  if (!data) {
    log_error("Invalid ftrace_hook_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for ftrace hook data.");
    return NULL;
  }

  // vcpu_id
  cJSON_AddNumberToObject(root, "vcpu_id", (double)data->vcpu_id);

  // Function name
  if (data->symname) {
    cJSON_AddStringToObject(root, "function", data->symname);
  }

  cJSON* regs = cJSON_CreateObject();
  if (!regs) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "regs", regs);
  cjson_add_hex_u64(regs, "rip", data->rip);
  cjson_add_hex_u64(regs, "rsp", data->rsp);
  cjson_add_hex_u64(regs, "cr3", data->cr3);
  cjson_add_hex_u64(regs, "rflags", data->rflags);

  cJSON* mem = cJSON_CreateObject();
  if (!mem) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "memory", mem);
  cjson_add_hex_u64(mem, "gla", data->gla);
  cjson_add_hex_u64(mem, "gpa", data->gpa);

  // Add modification details
  cJSON* modification = cJSON_CreateObject();
  if (!modification) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "modification", modification);
  cjson_add_hex_u64(modification, "original_value", data->original_value);
  cjson_add_hex_u64(modification, "current_value", data->current_value);

  if (data->value_type) {
    cJSON_AddStringToObject(modification, "value_type", data->value_type);
  }
  if (data->modification_type) {
    cJSON_AddStringToObject(modification, "type", data->modification_type);
  }

  return root;
}
