#include "state_callbacks/responses/kernel_module_list_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

kernel_module_list_state_data_t* kernel_module_list_state_data_new(void) {
  kernel_module_list_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for kernel module list state data.");
    return NULL;
  }

  data->modules = g_array_new(FALSE, FALSE, sizeof(kernel_module_info_t));
  if (!data->modules) {
    kernel_module_list_state_data_free(data);
    log_error("Failed to allocate array for kernel module list state data.");
    return NULL;
  }

  return data;
}

void kernel_module_list_state_data_free(kernel_module_list_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL kernel_module_list_state_data_t pointer.");
    return;
  }

  if (data->modules) {
    for (guint i = 0; i < data->modules->len; i++) {
      kernel_module_info_t* module =
          &g_array_index(data->modules, kernel_module_info_t, i);
      g_free(module->name);
      g_free(module->state);
      g_free(module->offset);
      if (module->used_by) {
        for (guint j = 0; j < module->used_by->len; j++) {
          char* used_by_name = g_array_index(module->used_by, char*, j);
          g_free(used_by_name);
        }
        g_array_free(module->used_by, TRUE);
      }
    }
    g_array_free(data->modules, TRUE);
  }

  g_free(data);
}

void kernel_module_list_state_add_module(
    kernel_module_list_state_data_t* data, const char* name, uint32_t size,
    uint32_t used_by_count, GArray* used_by, const char* state,
    const char* offset, uint64_t module_base, bool is_suspicious) {
  if (!data || !data->modules)
    return;

  kernel_module_info_t module = {
      .name = name ? g_strdup(name) : g_strdup("unknown"),
      .size = size,
      .used_by_count = used_by_count,
      .used_by = NULL,
      .state = state ? g_strdup(state) : g_strdup("unknown"),
      .offset = offset ? g_strdup(offset) : g_strdup("0x0"),
      .module_base = module_base,
      .is_suspicious = is_suspicious};

  // Copy used_by array if provided
  if (used_by && used_by->len > 0) {
    module.used_by = g_array_new(FALSE, FALSE, sizeof(char*));
    for (guint i = 0; i < used_by->len; i++) {
      char* used_by_name = g_array_index(used_by, char*, i);
      char* copied_name = g_strdup(used_by_name);
      g_array_append_val(module.used_by, copied_name);
    }
  } else {
    module.used_by = g_array_new(FALSE, FALSE, sizeof(char*));
  }

  g_array_append_val(data->modules, module);
}

void kernel_module_list_state_set_summary(kernel_module_list_state_data_t* data,
                                          uint32_t total_modules,
                                          uint32_t suspicious_modules) {
  if (!data)
    return;
  data->summary.total_modules = total_modules;
  data->summary.suspicious_modules = suspicious_modules;
}

cJSON* kernel_module_list_state_data_to_json(
    const kernel_module_list_state_data_t* data) {
  if (!data) {
    log_error("Invalid kernel_module_list_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error(
        "Failed to create cJSON object for kernel module list state data.");
    return NULL;
  }

  // Modules array
  cJSON* modules_array = cJSON_CreateArray();
  if (!modules_array) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "modules", modules_array);

  for (guint i = 0; i < data->modules->len; i++) {
    kernel_module_info_t* module =
        &g_array_index(data->modules, kernel_module_info_t, i);

    cJSON* module_obj = cJSON_CreateObject();
    if (!module_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddStringToObject(module_obj, "name", module->name);
    cJSON_AddNumberToObject(module_obj, "size", (double)module->size);
    cJSON_AddNumberToObject(module_obj, "used_by_count",
                            (double)module->used_by_count);

    // used_by array
    cJSON* used_by_array = cJSON_CreateArray();
    if (!used_by_array) {
      cJSON_Delete(root);
      return NULL;
    }
    cJSON_AddItemToObject(module_obj, "used_by", used_by_array);

    for (guint j = 0; j < module->used_by->len; j++) {
      char* used_by_name = g_array_index(module->used_by, char*, j);
      cJSON_AddItemToArray(used_by_array, cJSON_CreateString(used_by_name));
    }

    cJSON_AddStringToObject(module_obj, "state", module->state);
    cJSON_AddStringToObject(module_obj, "offset", module->offset);
    cjson_add_hex_u64(module_obj, "module_base", module->module_base);
    cjson_add_bool(module_obj, "is_suspicious", module->is_suspicious);

    cJSON_AddItemToArray(modules_array, module_obj);
  }

  // Summary section
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);
  cJSON_AddNumberToObject(summary, "total_modules",
                          (double)data->summary.total_modules);
  cJSON_AddNumberToObject(summary, "suspicious_modules",
                          (double)data->summary.suspicious_modules);

  return root;
}
