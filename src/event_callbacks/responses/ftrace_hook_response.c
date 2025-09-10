#include "event_callbacks/responses/ftrace_hook_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

static void maybe_add_access_decoded(cJSON* parent) {
  if (!parent)
    return;

  cJSON* dec = cJSON_CreateObject();
  if (!dec)
    return;

  if (cJSON_GetArraySize(dec) > 0) {
    cJSON_AddItemToObject(parent, "decoded", dec);
  } else {
    cJSON_Delete(dec);
  }
}

// NOLINTNEXTLINE
ftrace_hook_data_t* ftrace_hook_data_new(uint32_t vcpu_id, uint64_t rip,
                                         uint64_t gla, uint64_t gpa) {
  ftrace_hook_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for ftrace_hook_data_t.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->gla = gla;
  data->gpa = gpa;

  return data;
}

void ftrace_hook_data_free(ftrace_hook_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL ftrace_hook_data_t pointer.");
    return;
  }
  g_free(data);
}

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

  cJSON* regs = cJSON_CreateObject();
  if (!regs) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "regs", regs);
  cjson_add_hex_u64(regs, "rip", data->rip);

  cJSON* mem = cJSON_CreateObject();
  if (!mem) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "memory", mem);
  cjson_add_hex_u64(mem, "gla", data->gla);
  cjson_add_hex_u64(mem, "gpa", data->gpa);

  return root;
}
