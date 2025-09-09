#include "event_callbacks/responses/cr0_write_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>

void cjson_add_bool(cJSON* parent, const char* key, bool val) {
  cJSON_AddBoolToObject(parent, key, val);
}

void cr0_decode_flags(uint64_t cr0, cr0_flags_t* out_flags) {
  out_flags->protected_mode = (cr0 & CR0_PE) != 0;
  out_flags->write_protection = (cr0 & CR0_WP) != 0;
  out_flags->alignment_mask = (cr0 & CR0_AM) != 0;
  out_flags->cache_disable = (cr0 & CR0_CD) != 0;
  out_flags->paging_enable = (cr0 & CR0_PG) != 0;
}

// NOLINTNEXTLINE
cr0_write_data_t* cr0_write_data_new(uint32_t vcpu_id, uint64_t rip,
                                     uint64_t rsp, uint64_t cr3,
                                     uint64_t cr0_new) {
  cr0_write_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for CR0 write data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;

  cr0_decode_flags(cr0_new, &data->flags);

  return data;
}

void cr0_write_data_free(cr0_write_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL cr0_write_data_t pointer.");
    return;
  }
  g_free(data);
}

cJSON* cr0_write_data_to_json(const cr0_write_data_t* data) {
  if (!data) {
    log_error("Invalid cr0_write_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for CR0 write data.");
    return NULL;
  }

  // vcpu_id as a JSON number (cJSON stores numbers as doubles)
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

  cJSON* flags = cJSON_CreateObject();
  if (!flags) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "flags", flags);
  cjson_add_bool(flags, "protected_mode", data->flags.protected_mode);
  cjson_add_bool(flags, "write_protection", data->flags.write_protection);
  cjson_add_bool(flags, "alignment_mask", data->flags.alignment_mask);
  cjson_add_bool(flags, "cache_disable", data->flags.cache_disable);
  cjson_add_bool(flags, "paging_enable", data->flags.paging_enable);

  return root;
}