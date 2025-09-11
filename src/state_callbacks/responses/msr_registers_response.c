#include "state_callbacks/responses/msr_registers_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

msr_registers_state_data_t* msr_registers_state_data_new(void) {
  msr_registers_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for MSR registers state data.");
    return NULL;
  }

  data->vcpus = g_array_new(FALSE, FALSE, sizeof(vcpu_msr_info_t));
  if (!data->vcpus) {
    msr_registers_state_data_free(data);
    log_error("Failed to allocate array for MSR registers state data.");
    return NULL;
  }

  return data;
}

void msr_registers_state_data_free(msr_registers_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL msr_registers_state_data_t pointer.");
    return;
  }

  if (data->vcpus) {
    g_array_free(data->vcpus, TRUE);
  }

  if (data->legitimate_entry.symbol) {
    g_free(data->legitimate_entry.symbol);
  }

  g_free(data);
}

void msr_registers_state_set_kernel_range(msr_registers_state_data_t* data,
                                          uint64_t kernel_start,
                                          uint64_t kernel_end) {
  if (!data)
    return;
  data->kernel_start = kernel_start;
  data->kernel_end = kernel_end;
}

void msr_registers_state_set_legitimate_entry(msr_registers_state_data_t* data,
                                              uint64_t address,
                                              const char* symbol, bool found) {
  if (!data)
    return;
  data->legitimate_entry.address = address;
  data->legitimate_entry.found = found;
  if (symbol) {
    data->legitimate_entry.symbol = g_strdup(symbol);
  } else {
    data->legitimate_entry.symbol = g_strdup("unknown");
  }
}

void msr_registers_state_add_vcpu(msr_registers_state_data_t* data,
                                  uint32_t vcpu_id, uint64_t msr_lstar,
                                  bool is_in_kernel_text,
                                  bool matches_legitimate, bool is_suspicious) {
  if (!data || !data->vcpus)
    return;

  vcpu_msr_info_t vcpu_info = {.vcpu_id = vcpu_id,
                               .msr_lstar = msr_lstar,
                               .is_in_kernel_text = is_in_kernel_text,
                               .matches_legitimate = matches_legitimate,
                               .is_suspicious = is_suspicious};

  g_array_append_val(data->vcpus, vcpu_info);
}

void msr_registers_state_set_summary(msr_registers_state_data_t* data,
                                     uint32_t total_vcpus,
                                     uint32_t suspicious_vcpus) {
  if (!data)
    return;
  data->summary.total_vcpus = total_vcpus;
  data->summary.suspicious_vcpus = suspicious_vcpus;
  data->summary.kernel_text_start = data->kernel_start;
  data->summary.kernel_text_end = data->kernel_end;
}

cJSON* msr_registers_state_data_to_json(
    const msr_registers_state_data_t* data) {
  if (!data) {
    log_error("Invalid msr_registers_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for MSR registers state data.");
    return NULL;
  }

  // Kernel range section
  cJSON* kernel_range = cJSON_CreateObject();
  if (!kernel_range) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "kernel_range", kernel_range);
  cjson_add_hex_u64(kernel_range, "start", data->kernel_start);
  cjson_add_hex_u64(kernel_range, "end", data->kernel_end);

  // Legitimate syscall entry section
  cJSON* legitimate_entry = cJSON_CreateObject();
  if (!legitimate_entry) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "legitimate_syscall_entry", legitimate_entry);
  cjson_add_hex_u64(legitimate_entry, "address",
                    data->legitimate_entry.address);
  cJSON_AddStringToObject(legitimate_entry, "symbol",
                          data->legitimate_entry.symbol);
  cjson_add_bool(legitimate_entry, "found", data->legitimate_entry.found);

  // vCPUs section
  cJSON* vcpus_array = cJSON_CreateArray();
  if (!vcpus_array) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "vcpus", vcpus_array);

  for (guint i = 0; i < data->vcpus->len; i++) {
    vcpu_msr_info_t* vcpu = &g_array_index(data->vcpus, vcpu_msr_info_t, i);

    cJSON* vcpu_obj = cJSON_CreateObject();
    if (!vcpu_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddNumberToObject(vcpu_obj, "vcpu_id", (double)vcpu->vcpu_id);
    cjson_add_hex_u64(vcpu_obj, "msr_lstar", vcpu->msr_lstar);
    cjson_add_bool(vcpu_obj, "is_in_kernel_text", vcpu->is_in_kernel_text);
    cjson_add_bool(vcpu_obj, "matches_legitimate", vcpu->matches_legitimate);
    cjson_add_bool(vcpu_obj, "is_suspicious", vcpu->is_suspicious);

    cJSON_AddItemToArray(vcpus_array, vcpu_obj);
  }

  // Summary section
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);
  cJSON_AddNumberToObject(summary, "total_vcpus",
                          (double)data->summary.total_vcpus);
  cJSON_AddNumberToObject(summary, "suspicious_vcpus",
                          (double)data->summary.suspicious_vcpus);
  cjson_add_hex_u64(summary, "kernel_text_start",
                    data->summary.kernel_text_start);
  cjson_add_hex_u64(summary, "kernel_text_end", data->summary.kernel_text_end);

  return root;
}
