#include "state_callbacks/responses/idt_table_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

idt_table_state_data_t* idt_table_state_data_new(void) {
  idt_table_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for IDT table state data.");
    return NULL;
  }

  data->vcpu_infos = g_array_new(FALSE, FALSE, sizeof(vcpu_idt_info_t));
  data->handlers = g_array_new(FALSE, FALSE, sizeof(idt_handler_info_t));

  if (!data->vcpu_infos || !data->handlers) {
    idt_table_state_data_free(data);
    log_error("Failed to allocate arrays for IDT table state data.");
    return NULL;
  }

  return data;
}

void idt_table_state_set_kernel_range(idt_table_state_data_t* data,
                                      uint64_t kernel_start,
                                      uint64_t kernel_end) {
  if (!data)
    return;
  data->kernel_start = kernel_start;
  data->kernel_end = kernel_end;
}

void idt_table_state_add_vcpu_info(idt_table_state_data_t* data,
                                   uint32_t vcpu_id, uint64_t idt_base) {
  if (!data || !data->vcpu_infos)
    return;

  vcpu_idt_info_t info = {.vcpu_id = vcpu_id, .idt_base = idt_base};

  g_array_append_val(data->vcpu_infos, info);
}

void idt_table_state_add_hooked_handler(idt_table_state_data_t* data,
                                        uint32_t vcpu_id, uint16_t vector,
                                        const char* name,
                                        uint64_t handler_address,
                                        bool is_hooked) {
  if (!data || !data->handlers)
    return;

  idt_handler_info_t handler = {
      .vcpu_id = vcpu_id,
      .vector = vector,
      .name = name ? g_strdup(name) : g_strdup("unknown"),
      .handler_address = handler_address,
      .is_hooked = is_hooked};

  g_array_append_val(data->handlers, handler);
}

void idt_table_state_set_summary(idt_table_state_data_t* data, int total_hooked,
                                 bool vcpu_inconsistency) {
  if (!data)
    return;
  data->total_hooked = total_hooked;
  data->vcpu_inconsistency = vcpu_inconsistency;
}

void idt_table_state_data_free(idt_table_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL idt_table_state_data_t pointer.");
    return;
  }

  if (data->handlers) {
    // Free handler name strings
    for (guint i = 0; i < data->handlers->len; i++) {
      idt_handler_info_t* handler =
          &g_array_index(data->handlers, idt_handler_info_t, i);
      if (handler->name) {
        g_free(handler->name);
      }
    }
    g_array_free(data->handlers, TRUE);
  }

  if (data->vcpu_infos) {
    g_array_free(data->vcpu_infos, TRUE);
  }

  g_free(data);
}

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