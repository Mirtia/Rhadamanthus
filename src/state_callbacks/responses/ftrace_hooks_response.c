#include "state_callbacks/responses/ftrace_hooks_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

ftrace_hooks_state_data_t* ftrace_hooks_state_data_new(void) {
  ftrace_hooks_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for ftrace hooks state data.");
    return NULL;
  }

  data->loaded_programs = g_array_new(FALSE, FALSE, sizeof(ftrace_hook_info_t));
  if (!data->loaded_programs) {
    ftrace_hooks_state_data_free(data);
    log_error("Failed to allocate array for ftrace hooks state data.");
    return NULL;
  }

  data->attachment_points =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  if (!data->attachment_points) {
    ftrace_hooks_state_data_free(data);
    log_error("Failed to allocate hash table for ftrace hooks state data.");
    return NULL;
  }

  data->summary.hooks_by_type =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  if (!data->summary.hooks_by_type) {
    ftrace_hooks_state_data_free(data);
    log_error(
        "Failed to allocate hooks by type hash table for ftrace hooks state "
        "data.");
    return NULL;
  }

  return data;
}

void ftrace_hooks_state_data_free(ftrace_hooks_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL ftrace_hooks_state_data_t pointer.");
    return;
  }

  if (data->loaded_programs) {
    for (guint i = 0; i < data->loaded_programs->len; i++) {
      ftrace_hook_info_t* hook =
          &g_array_index(data->loaded_programs, ftrace_hook_info_t, i);
      g_free(hook->type);
      g_free(hook->name);
      g_free(hook->attach_type);
      g_free(hook->flags);
      g_free(hook->hook_reason);
    }
    g_array_free(data->loaded_programs, TRUE);
  }

  if (data->attachment_points) {
    g_hash_table_destroy(data->attachment_points);
  }

  if (data->summary.hooks_by_type) {
    g_hash_table_destroy(data->summary.hooks_by_type);
  }

  g_free(data);
}

void ftrace_hooks_state_add_hook(ftrace_hooks_state_data_t* data, uint32_t id,
                                 const char* type, const char* name,
                                 const char* attach_type,
                                 uint64_t function_addr, const char* flags,
                                 uint64_t trampoline_addr,
                                 uint64_t saved_func_addr, bool is_suspicious,
                                 const char* hook_reason) {
  if (!data || !data->loaded_programs)
    return;

  ftrace_hook_info_t hook = {
      .id = id,
      .type = type ? g_strdup(type) : g_strdup("ftrace_hook"),
      .name = name ? g_strdup(name) : g_strdup("unknown"),
      .attach_type = attach_type ? g_strdup(attach_type) : g_strdup("unknown"),
      .function_addr = function_addr,
      .flags = flags ? g_strdup(flags) : g_strdup("0x0"),
      .trampoline_addr = trampoline_addr,
      .saved_func_addr = saved_func_addr,
      .is_suspicious = is_suspicious,
      .hook_reason = hook_reason ? g_strdup(hook_reason) : NULL};

  g_array_append_val(data->loaded_programs, hook);
}

void ftrace_hooks_state_add_attachment_point(ftrace_hooks_state_data_t* data,
                                             const char* attach_type,
                                             uint32_t hook_id) {
  if (!data || !data->attachment_points || !attach_type)
    return;

  GArray* ids = g_hash_table_lookup(data->attachment_points, attach_type);
  if (!ids) {
    ids = g_array_new(FALSE, FALSE, sizeof(uint32_t));
    g_hash_table_insert(data->attachment_points, g_strdup(attach_type), ids);
  }
  g_array_append_val(ids, hook_id);
}

void ftrace_hooks_state_set_summary(ftrace_hooks_state_data_t* data,
                                    uint32_t total_hooks,
                                    uint32_t suspicious_hooks,
                                    bool global_ftrace_enabled,
                                    uint32_t commonly_hooked_syscalls) {
  if (!data)
    return;
  data->summary.total_hooks = total_hooks;
  data->summary.suspicious_hooks = suspicious_hooks;
  data->summary.global_ftrace_enabled = global_ftrace_enabled;
  data->summary.commonly_hooked_syscalls = commonly_hooked_syscalls;
}

cJSON* ftrace_hooks_state_data_to_json(const ftrace_hooks_state_data_t* data) {
  if (!data) {
    log_error("Invalid ftrace_hooks_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for ftrace hooks state data.");
    return NULL;
  }

  // loaded_programs array
  cJSON* programs_array = cJSON_CreateArray();
  if (!programs_array) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "loaded_programs", programs_array);

  for (guint i = 0; i < data->loaded_programs->len; i++) {
    ftrace_hook_info_t* hook =
        &g_array_index(data->loaded_programs, ftrace_hook_info_t, i);

    cJSON* hook_obj = cJSON_CreateObject();
    if (!hook_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddNumberToObject(hook_obj, "id", (double)hook->id);
    cJSON_AddStringToObject(hook_obj, "type", hook->type);
    cJSON_AddStringToObject(hook_obj, "name", hook->name);
    cJSON_AddStringToObject(hook_obj, "attach_type", hook->attach_type);
    cjson_add_hex_u64(hook_obj, "function_addr", hook->function_addr);
    cJSON_AddStringToObject(hook_obj, "flags", hook->flags);
    cjson_add_hex_u64(hook_obj, "trampoline_addr", hook->trampoline_addr);
    cjson_add_hex_u64(hook_obj, "saved_func_addr", hook->saved_func_addr);
    cjson_add_bool(hook_obj, "is_suspicious", hook->is_suspicious);
    if (hook->hook_reason) {
      cJSON_AddStringToObject(hook_obj, "hook_reason", hook->hook_reason);
    } else {
      cJSON_AddNullToObject(hook_obj, "hook_reason");
    }

    cJSON_AddItemToArray(programs_array, hook_obj);
  }

  // attachment_points object
  cJSON* attachment_points = cJSON_CreateObject();
  if (!attachment_points) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "attachment_points", attachment_points);

  GHashTableIter iter;
  gpointer key, value;
  g_hash_table_iter_init(&iter, data->attachment_points);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    const char* attach_type = (const char*)key;
    GArray* ids = (GArray*)value;

    cJSON* ids_array = cJSON_CreateArray();
    if (!ids_array) {
      cJSON_Delete(root);
      return NULL;
    }

    for (guint j = 0; j < ids->len; j++) {
      uint32_t id = g_array_index(ids, uint32_t, j);
      cJSON_AddItemToArray(ids_array, cJSON_CreateNumber((double)id));
    }

    cJSON_AddItemToObject(attachment_points, attach_type, ids_array);
  }

  // Summary section
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);
  cJSON_AddNumberToObject(summary, "total_hooks",
                          (double)data->summary.total_hooks);
  cJSON_AddNumberToObject(summary, "suspicious_hooks",
                          (double)data->summary.suspicious_hooks);
  cjson_add_bool(summary, "global_ftrace_enabled",
                 data->summary.global_ftrace_enabled);
  cJSON_AddNumberToObject(summary, "commonly_hooked_syscalls",
                          (double)data->summary.commonly_hooked_syscalls);

  // hooks_by_type object
  cJSON* hooks_by_type = cJSON_CreateObject();
  if (!hooks_by_type) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(summary, "hooks_by_type", hooks_by_type);

  GHashTableIter type_iter;
  gpointer type_key, type_value;
  g_hash_table_iter_init(&type_iter, data->summary.hooks_by_type);
  while (g_hash_table_iter_next(&type_iter, &type_key, &type_value)) {
    const char* hook_type = (const char*)type_key;
    uint32_t* count = (uint32_t*)type_value;
    cJSON_AddNumberToObject(hooks_by_type, hook_type, (double)*count);
  }

  return root;
}
