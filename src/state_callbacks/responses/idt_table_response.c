#include "state_callbacks/responses/idt_table_response.h"
#include <log.h>
#include "utils.h"

cJSON* idt_table_state_data_to_json(const idt_table_state_data_t* data) {
  if (!data) {
    log_error("Invalid idt_table_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for IDT table state data.");
    return NULL;
  }

  // Kernel range information
  cJSON* kernel_range = cJSON_CreateObject();
  if (!kernel_range) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "kernel_range", kernel_range);
  cjson_add_hex_u64(kernel_range, "start", data->kernel_start);
  cjson_add_hex_u64(kernel_range, "end", data->kernel_end);

  // vCPU information
  cJSON* vcpus = cJSON_CreateArray();
  if (!vcpus) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "vcpus", vcpus);

  for (guint i = 0; i < data->vcpu_infos->len; i++) {
    vcpu_idt_info_t* vcpu_info =
        &g_array_index(data->vcpu_infos, vcpu_idt_info_t, i);

    cJSON* vcpu_obj = cJSON_CreateObject();
    if (!vcpu_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddNumberToObject(vcpu_obj, "vcpu_id", (double)vcpu_info->vcpu_id);
    cjson_add_hex_u64(vcpu_obj, "idt_base", vcpu_info->idt_base);

    cJSON_AddItemToArray(vcpus, vcpu_obj);
  }

  // Handler information
  cJSON* handlers = cJSON_CreateArray();
  if (!handlers) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "handlers", handlers);

  for (guint i = 0; i < data->handlers->len; i++) {
    idt_handler_info_t* handler =
        &g_array_index(data->handlers, idt_handler_info_t, i);

    cJSON* handler_obj = cJSON_CreateObject();
    if (!handler_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddNumberToObject(handler_obj, "vcpu_id", (double)handler->vcpu_id);
    cJSON_AddNumberToObject(handler_obj, "vector", (double)handler->vector);
    cJSON_AddStringToObject(handler_obj, "name",
                            handler->name ? handler->name : "unknown");
    cjson_add_hex_u64(handler_obj, "handler_address", handler->handler_address);
    cjson_add_bool(handler_obj, "is_hooked", handler->is_hooked);

    cJSON_AddItemToArray(handlers, handler_obj);
  }

  // Summary information (without threat level)
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);

  cJSON_AddNumberToObject(summary, "total_hooked_handlers",
                          (double)data->total_hooked);
  cjson_add_bool(summary, "vcpu_inconsistency", data->vcpu_inconsistency);

  return root;
}