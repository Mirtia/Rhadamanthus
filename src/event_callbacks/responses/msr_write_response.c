#include "event_callbacks/responses/msr_write_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "state_callbacks/responses/msr_registers_response.h"
#include "utils.h"

const char* msr_get_name(uint64_t msr_index) {
  switch (msr_index) {
    case MSR_IA32_LSTAR:
      return "IA32_LSTAR";
    case MSR_IA32_CSTAR:
      return "IA32_CSTAR";
    case MSR_IA32_FMASK:
      return "IA32_FMASK";
    case MSR_IA32_KERNEL_GS_BASE:
      return "IA32_KERNEL_GS_BASE";
    case MSR_IA32_SYSENTER_CS:
      return "IA32_SYSENTER_CS";
    case MSR_IA32_SYSENTER_ESP:
      return "IA32_SYSENTER_ESP";
    case MSR_IA32_SYSENTER_EIP:
      return "IA32_SYSENTER_EIP";
    case MSR_IA32_EFER:
      return "IA32_EFER";
    case MSR_IA32_STAR:
      return "IA32_STAR";
    default:
      return NULL;
  }
}

bool msr_needs_further_investigation(uint64_t msr_index) {
  switch (msr_index) {
    case MSR_IA32_LSTAR:           // System call entry point
    case MSR_IA32_CSTAR:           // Compat mode system call entry
    case MSR_IA32_FMASK:           // System call flag mask
    case MSR_IA32_KERNEL_GS_BASE:  // Kernel GS base
    case MSR_IA32_SYSENTER_CS:     // SYSENTER CS
    case MSR_IA32_SYSENTER_ESP:    // SYSENTER ESP
    case MSR_IA32_SYSENTER_EIP:    // SYSENTER EIP
    case MSR_IA32_EFER:            // Extended feature enable
    case MSR_IA32_STAR:            // System call target address
      return true;
    default:
      return false;
  }
}

msr_write_data_t* msr_write_data_new(uint32_t vcpu_id, uint64_t rip,
                                     uint64_t rsp, uint64_t cr3,
                                     uint64_t msr_index, uint64_t msr_value) {
  msr_write_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for MSR write data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->msr_index = msr_index;
  data->msr_value = msr_value;

  const char* name = msr_get_name(msr_index);
  if (name) {
    data->msr_name = g_strdup(name);
    if (!data->msr_name) {
      g_free(data);
      log_error("Failed to allocate memory for MSR name.");
      return NULL;
    }
  } else {
    data->msr_name = NULL;
  }

  return data;
}

void msr_write_data_free(msr_write_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL msr_write_data_t pointer.");
    return;
  }

  if (data->msr_name) {
    g_free(data->msr_name);
  }

  g_free(data);
}

cJSON* msr_write_data_to_json(const msr_write_data_t* data) {
  if (!data) {
    log_error("Invalid msr_write_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for MSR write data.");
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

  // MSR information
  cJSON* msr = cJSON_CreateObject();
  if (!msr) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "msr", msr);

  cjson_add_hex_u64(msr, "index", data->msr_index);
  cjson_add_hex_u64(msr, "value", data->msr_value);

  if (data->msr_name) {
    cJSON_AddStringToObject(msr, "name", data->msr_name);
  } else {
    cJSON_AddStringToObject(msr, "name", "unknown");
  }

  return root;
}